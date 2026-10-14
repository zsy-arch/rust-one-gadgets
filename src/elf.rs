//! ELF 解析：段、符号表、build-id、字符串定位。
//!
//! 用 goblin 读取，全部数据一次性拷入内存（libc ~2MB，读一次 `File::read`）。
//! 关键输出：
//! - 可执行段的字节 + 装载基址（vaddr → 文件偏移换算）
//! - `.dynsym` / `.symtab` 里 exec*/posix_spawn* 符号地址
//! - NT_GNU_BUILD_ID
//! - `/bin/sh`、`sh` 字符串的文件偏移（gadget 校验用）

use crate::error::Result;
use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_RISCV, EM_X86_64};
use goblin::elf::Elf;

/// 目标架构（决定反汇编位宽与模拟器语义）。
/// Mips 变体（o32 BE/LE）由 `Libc.mips_el` 区分。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X64,
    X86,
    Aarch64,
    Arm,
    Riscv64,
    Mips,
}

/// 一个可装载段的视图：文件偏移 ↔ 虚拟地址。
pub struct Segment {
    /// 文件内偏移。
    pub file_off: u64,
    /// 装载到的虚拟地址（= one_gadget 语义里的 libc 相对地址）。
    pub vaddr: u64,
    /// 文件内数据长度（memsz 可能更大，bss 不在文件里）。
    pub file_size: u64,
    pub executable: bool,
}

/// 解析后的 libc ELF。
pub struct Libc {
    pub data: Vec<u8>,
    pub segments: Vec<Segment>,
    /// 反汇编/模拟器用的架构判定。
    pub arch: Arch,
    /// mips 端序（true = little；仅 Arch::Mips 有意义）。
    #[allow(dead_code)] // mips 切片接入后使用
    pub mips_el: bool,
    /// 地址 → 符号名（dynsym + symtab 中带名字的函数符号）。
    pub symbol_names: std::collections::HashMap<u64, String>,
    /// 地址 → objdump 风格带版本符号（`name@@GLIBC_2.2.5`），注释渲染用。
    symbols_versioned: std::collections::HashMap<u64, String>,
    /// symbol_names 的地址升序表（nearest_symbol 二分用）。
    symbol_addrs: Vec<u64>,
    /// 符号名 → 地址集合（--near 的 function_offset 用）。
    symbols_by_name: std::collections::HashMap<String, Vec<u64>>,
    /// `/bin/sh` 在文件中的偏移（以 NUL 结尾搜索）。
    pub bin_sh_offset: Option<u64>,
    /// DT_PLTGOT 的值（i386 的 GOT 基准，GOT-relative /bin/sh 判定用）。
    pub pltgot: Option<u64>,
    /// NT_GNU_BUILD_ID（hex 小写；无 note 段为 None）。
    pub build_id: Option<String>,
    /// 未定义 dynsym 符号名（--near 的 GOT 函数集），带 GLIBC 版本。
    imports_glibc: Vec<String>,
}

impl Libc {
    /// i386 的 `rel_sh`：GOT 与 /bin/sh 的相对距离（one_gadget I386#rel_sh）。
    pub fn rel_sh(&self) -> Option<u64> {
        match (self.pltgot, self.bin_sh_offset) {
            (Some(g), Some(s)) if g >= s => Some(g - s),
            _ => None,
        }
    }
}

impl Libc {
    /// 解析一个 libc 文件。
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let elf = Elf::parse(&data).map_err(|e| crate::error::RogError::ElfParse(e.to_string()))?;
            let segments: Vec<Segment> = elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|p| Segment {
                file_off: p.p_offset,
                vaddr: p.p_vaddr,
                file_size: p.p_filesz,
                executable: p.is_executable(),
            })
            .collect();

        // 地址 → 符号名（函数与对象都留；call/rip 解引用都可能用到）
        let mut symbol_names = std::collections::HashMap::new();
        for (syms, strtab) in [(&elf.dynsyms, &elf.dynstrtab), (&elf.syms, &elf.strtab)] {
            for sym in syms.iter() {
                if sym.st_value == 0 {
                    continue;
                }
                if let Some(name) = strtab.get_at(sym.st_name) {
                    symbol_names.entry(sym.st_value).or_insert_with(|| name.to_string());
                }
            }
        }

        let bin_sh_offset = find_cstr(&data, b"/bin/sh\0");

        // versym 序号 → 版本串（verdef 自身定义 + verneed 引入库版本）
        let version_index = version_map(&elf);
        // objdump 风格带版本符号表（只有 dynsym 参与 symbol versioning）
        let mut symbols_versioned = std::collections::HashMap::new();
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if sym.st_value == 0 {
                continue;
            }
            let Some(name) = elf.dynstrtab.get_at(sym.st_name) else { continue };
            let vs = elf
                .versym
                .as_ref()
                .and_then(|v| v.get_at(i))
                .map(|v| v.vs_val)
                .unwrap_or(0);
            let annotated = if vs == 0 || vs == 1 {
                // 0=local, 1=global：无版本
                name.to_string()
            } else if let Some(ver) = version_index.get(&vs) {
                // 0x8000 位是 hidden 标志，去掉
                format!("{name}@{ver}")
            } else {
                name.to_string()
            };
            // objdump（BFD）同地址多符号的选择：实测 libc 双 weak 别名
            // （sigaction/__sigaction）时 BFD 显示 `__sigaction`。对齐之：
            // `__` 前缀名优先；其次带 @@ 的 default 版本。
            symbols_versioned
                .entry(sym.st_value)
                .and_modify(|e: &mut String| {
                    let e_under = e.starts_with("__");
                    let n_under = annotated.starts_with("__");
                    let better = (n_under && !e_under)
                        || (n_under == e_under && !e.contains("@@") && annotated.contains("@@"));
                    if better {
                        *e = annotated.clone();
                    }
                })
                .or_insert(annotated);
        }

        let mut symbol_addrs: Vec<u64> = symbol_names.keys().copied().collect();
        symbol_addrs.sort_unstable();
        // 名 → 地址集合：直接从两张符号表收集（同地址多别名都保留；
        // --near 的 objdump -T grep 语义本就按名字匹配所有行）
        let mut symbols_by_name: std::collections::HashMap<String, Vec<u64>> =
            std::collections::HashMap::new();
        for (syms, strtab) in [(&elf.dynsyms, &elf.dynstrtab), (&elf.syms, &elf.strtab)] {
            for sym in syms.iter() {
                if sym.st_value == 0 {
                    continue;
                }
                if let Some(name) = strtab.get_at(sym.st_name) {
                    let v = symbols_by_name.entry(name.to_string()).or_default();
                    if !v.contains(&sym.st_value) {
                        v.push(sym.st_value);
                    }
                }
            }
        }
        let machine = elf.header.e_machine;
        // 带版本符号名集合（Ruby got_functions：objdump -T | grep -iPo 'GLIBC_.+?\s+\K.*'）。
        // 版本串以 GLIBC 开头（GLIBC_2.x / GLIBC_PRIVATE），定义与否不限——libc 自身的
        // 版本化导出同样命中该 grep。
        let imports_glibc: Vec<String> = elf
            .dynsyms
            .iter()
            .enumerate()
            .filter_map(|(i, sym)| {
                let name = elf.dynstrtab.get_at(sym.st_name)?;
                let vs = elf.versym.as_ref().and_then(|v| v.get_at(i)).map(|v| v.vs_val)?;
                let ver = version_index.get(&vs)?;
                ver.starts_with("GLIBC").then(|| name.to_string())
            })
            .collect();
        // DT_PLTGOT（i386 GOT 基准）。goblin 的 dynamic.pltgot 已换算 vaddr。
        // goblin 0.9 的 Dynamic 没直接暴露 pltgot —— 从动态段条目里取 DT_PLTGOT。
        // 注意 goblin 的 d_val 已是 vaddr（dynamic_pltgot 未做 vm→off 换算）。
        let pltgot = elf
            .dynamic
            .as_ref()
            .and_then(|d| d.dyns.iter().find(|e| e.d_tag == goblin::elf::dynamic::DT_PLTGOT))
            .map(|e| e.d_val);
        // NT_GNU_BUILD_ID：遍历 PT_NOTE 段（.note.gnu.build-id）
        let build_id = elf
            .iter_note_headers(&data)
            .and_then(|mut it| {
                it.find_map(|n| {
                    n.ok().and_then(|n| {
                        if n.n_type == goblin::elf::note::NT_GNU_BUILD_ID {
                            Some(n.desc.iter().map(|b| format!("{b:02x}")).collect::<String>())
                        } else {
                            None
                        }
                    })
                })
            });
        let arch = if machine == EM_X86_64 {
            Arch::X64
        } else if machine == EM_386 {
            Arch::X86
        } else if machine == EM_AARCH64 {
            Arch::Aarch64
        } else if machine == EM_ARM {
            Arch::Arm
        } else if machine == EM_RISCV {
            Arch::Riscv64
        } else if machine == EM_MIPS {
            Arch::Mips
        } else {
            return Err(crate::error::RogError::UnsupportedArch(machine));
        };
        // mips 端序：e_ident EI_DATA（ELFDATA2MSB=2）
        let mips_el = arch != Arch::Mips || elf.header.e_ident[5] != 2;
        Ok(Libc { data, segments, arch, mips_el,
            symbol_names,
            symbols_versioned,
            symbol_addrs,
            symbols_by_name,
            bin_sh_offset,
            pltgot,
            build_id,
            imports_glibc,
        })
    }

    /// 函数名 → libc 偏移（dynsym 精确匹配；未定义/未找到为 None）。
    ///
    /// 对齐 Ruby objdump -T 首行语义：同名多符号取**地址最小**者。
    pub fn function_offset(&self, name: &str) -> Option<u64> {
        self.symbols_by_name.get(name).and_then(|v| v.iter().min().copied())
    }

    /// GOT 引用的 GLIBC 函数集（--near ELF 文件模式）。
    pub fn imported_glibc_functions(&self) -> Vec<String> {
        self.imports_glibc.clone()
    }

    /// 是否是 x86-64 ELF。
    pub fn is_x86_64(&self) -> bool {
        self.arch == Arch::X64
    }

    /// 主可执行段（含 .text）。
    pub fn executable_segment(&self) -> Option<&Segment> {
        self.segments.iter().find(|s| s.executable)
    }

    /// 虚拟地址 → 文件偏移（找不到返回 None）。
    pub fn vaddr_to_off(&self, vaddr: u64) -> Option<u64> {
        self.segments
            .iter()
            .find(|s| vaddr >= s.vaddr && vaddr < s.vaddr + s.file_size)
            .map(|s| vaddr - s.vaddr + s.file_off)
    }

    /// 虚拟地址处的字节切片（可执行段内）。
    pub fn bytes_at_vaddr(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        let off = self.vaddr_to_off(vaddr)?;
        self.data.get(off as usize..off as usize + len)
    }

    /// objdump 注释语义：精确命中取带版本名；否则 `nearest_sym+offset`。
    ///
    /// objdump 的注释源是 .symtab（含局部符号），偏移形式 `<sym+0x18b>`；
    /// 没有任何符号时只显示地址。
    pub fn nearest_symbol(&self, addr: u64) -> String {
        if let Some(s) = self.symbols_versioned.get(&addr) {
            return s.clone();
        }
        // 最近的不超过 addr 的符号（预排序地址表二分）
        let pos = self.symbol_addrs.binary_search(&addr);
        let base = match pos {
            Ok(i) => Some(self.symbol_addrs[i]),
            Err(0) => None,
            Err(i) => Some(self.symbol_addrs[i - 1]),
        };
        match base {
            Some(a) if a == addr => {
                self.symbol_names.get(&a).cloned().unwrap_or_default()
            }
            Some(a) => {
                let name = self.symbol_names.get(&a).cloned().unwrap_or_default();
                format!("{name}+{:#x}", addr - a)
            }
            None => String::new(),
        }
    }
}

/// versym 序号 → 版本名字符串。
///
/// verdef：本库定义的版本（GLIBC_PRIVATE、GLIBC_2.2.5 等）；
/// verneed：依赖库提供的版本（同样挂在 versym 序号上）。
/// 两者的名字都在 dynstrtab。
fn version_map(elf: &Elf) -> std::collections::HashMap<u16, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(vd) = &elf.verdef {
        for entry in vd.iter() {
            // verdaux 首项是版本名
            if let Some(aux) = entry.iter().next() {
                if let Some(name) = elf.dynstrtab.get_at(aux.vda_name) {
                    map.insert(entry.vd_ndx, name.to_string());
                }
            }
        }
    }
    if let Some(vn) = &elf.verneed {
        for need in vn.iter() {
            for aux in need.iter() {
                if let Some(name) = elf.dynstrtab.get_at(aux.vna_name) {
                    map.insert(aux.vna_other, name.to_string());
                }
            }
        }
    }
    map
}

/// 在文件里找 `needle`，返回文件偏移。
fn find_cstr(data: &[u8], needle: &[u8]) -> Option<u64> {
    data.windows(needle.len()).position(|w| w == needle).map(|i| i as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小 x86-64 ELF 手工拼装：64 字节 ELF头 + 1 个 PT_LOAD 可执行段。
    fn minimal_elf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];
        // e_ident
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EV_CURRENT
        // e_type = ET_DYN
        buf[16..18].copy_from_slice(&3u16.to_le_bytes());
        // e_machine = EM_X86_64 (62)
        buf[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_ehsize = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_phentsize = 56, e_phnum = 1, e_phoff = 64
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        // Phdr at 64: PT_LOAD(1), flags RX=5, offset=0x100, vaddr=0x100, filesz=0x100
        let ph = &mut buf[64..120];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // p_type
        ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // p_flags
        ph[8..16].copy_from_slice(&0x100u64.to_le_bytes()); // p_offset
        ph[16..24].copy_from_slice(&0x100u64.to_le_bytes()); // p_vaddr
        ph[32..40].copy_from_slice(&0x100u64.to_le_bytes()); // p_filesz
        // 代码段里放个 "/bin/sh"
        buf.resize(0x200, 0);
        buf[0x100..0x108].copy_from_slice(b"/bin/sh\0");
        buf
    }

    #[test]
    fn test_parse_minimal() {
        let data = minimal_elf();
        let libc = Libc::parse(data).expect("parse");
        assert!(libc.is_x86_64());
        assert_eq!(libc.bin_sh_offset, Some(0x100));
        assert_eq!(libc.executable_segment().map(|s| s.vaddr), Some(0x100));
        assert_eq!(libc.vaddr_to_off(0x100), Some(0x100));
    }

    #[test]
    fn test_reject_garbage() {
        assert!(Libc::parse(vec![1, 2, 3, 4, 5]).is_err());
    }

    #[test]
    fn test_find_cstr_finds_needle() {
        let data = b"abc\0sh\0def".to_vec();
        assert_eq!(find_cstr(&data, b"\0sh\0"), Some(3));
        assert_eq!(find_cstr(&data, b"/bin/sh\0"), None);
    }
}

