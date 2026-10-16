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
    pub mips_el: bool,
    /// mips e_flags 的 EF_MIPS_ARCH 位域（0=mips1 … 5=mips32r2 6=mips64r2 …）；
    /// ≥5 视为 r2+（rdhwr/seb/seh/ext/ins/wsbh/rotr 可用）。
    pub mips_arch_level: u8,
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
    /// arm：dynsym STT_FUNC 的 ISA 边界表（地址升序，(addr, thumb?)）。
    /// 只在切换点保留（chunk_while 同值合并），与 master arm.rb#record_instruction_sets 一致。
    pub arm_isa_chunks: Vec<(u64, bool)>,
    /// arm：dynsym STT_FUNC 起点（对齐后，升序去重）—— objdump 符号范围端点。
    pub arm_sym_starts: Vec<u64>,
    /// mips：dynsym STT_FUNC 起点（升序去重）—— objdump -d 的 stop_offset 端点
    /// （disassemble_section 逐符号分段；无 symtab 的 stripped libc 只用 .dynsym）。
    pub mips_func_starts: Vec<u64>,
    /// mips：objdump -d 反汇编的 AX section 序（(vaddr, size)，升序）。
    pub mips_code_sections: Vec<(u64, u64)>,
    /// arm：objdump -d 的逐函数解码范围（不相交并集，升序）。
    /// thumb 符号范围为 [v&~1, v+st_size)（st_size 从奇数值起算 → 掩码起点多 1 字节，
    /// 产生"函数尾多解码 1 条 2 字节指令"的 objdump 行为）；函数间池/padding 不解码。
    /// arm：.symtab 的 $a/$t/$d mapping symbols（地址升序；(addr, kind)）。
    /// objdump 依此切 ISA 与数据段（$d → .word）；空表 = 无 symtab（stripped）。
    pub arm_map_syms: Vec<(u64, u8)>,
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

        // arm：thumb 函数 st_value 位 0 置位；objdump 注释用对齐值（& !1）
        let is_arm = elf.header.e_machine == goblin::elf::header::EM_ARM;
        let is_mips = elf.header.e_machine == EM_MIPS;
        // 地址 → 符号名（函数与对象都留；call/rip 解引用都可能用到）
        let mut symbol_names = std::collections::HashMap::new();
        // (size, name) 胜者跟踪（同地址多符号的 objdump 选择序）
        let mut symbol_sizes: std::collections::HashMap<u64, (u64, String)> =
            std::collections::HashMap::new();
        let mut dynsym_addrs: std::collections::HashSet<u64> = std::collections::HashSet::new();
        // arm $a/$t/$d mapping symbols（objdump 的 ISA/数据切换源）
        let mut arm_map_syms: Vec<(u64, u8)> = Vec::new();
        for (table_idx, (syms, strtab)) in
            [(&elf.dynsyms, &elf.dynstrtab), (&elf.syms, &elf.strtab)]
                .into_iter()
                .enumerate()
        {
            let first_table = table_idx == 0;
            for sym in syms.iter() {
                if sym.st_value == 0 {
                    continue;
                }
                // STT_SECTION（无名）：bfd canonicalize 后 value=0，不参与地址
                // 基准（否则 `.text` SECTION 符号以 sh_addr 值污染 nearest）。
                // SHN_UNDEF：MIPS 未定义符号也带 value（ld.so 提示地址），同样污染。
                if sym.st_type() == goblin::elf::sym::STT_SECTION
                    || sym.st_shndx == 0
                {
                    continue;
                }
                if let Some(n) = strtab.get_at(sym.st_name) {
                    // ARM mapping symbols（$a/$t/$d 及 $t.x/$d.x…）：objdump 的
                    // nearest-symbol 查找跳过（打印 <fn+off> 而非 <$d+off>）；
                    // 但 $a/$t/$d 本身收进 arm_map_syms 供 disassemble_range 切换
                    if is_arm
                        && n.len() >= 2
                        && n.as_bytes()[0] == b'$'
                        && matches!(n.as_bytes()[1], b'a' | b't' | b'd')
                    {
                        if n.len() <= 2 || n.as_bytes()[2] == b'.' {
                            arm_map_syms.push((
                                sym.st_value,
                                match n.as_bytes()[1] {
                                    b'a' => 0,
                                    b't' => 1,
                                    _ => 2,
                                },
                            ));
                        }
                        continue;
                    }
                }
                let sv = if is_arm { sym.st_value & !1 } else { sym.st_value };
                if let Some(name) = strtab.get_at(sym.st_name) {
                    // 同地址多符号（uclibc .symtab 的 __aeabi_* 别名等）：objdump
                    // 取 st_size 大者优先 → 名字字典序；但 dynsym 行整体优先
                    let better = !dynsym_addrs.contains(&sv)
                        && symbol_sizes
                            .get(&sv)
                            .is_none_or(|&(sz0, ref n0)| {
                                // 全局/弱保持 dynsym 别名表语义：size 降序，名字升序
                                (std::cmp::Reverse(sym.st_size), name.to_string())
                                    < (std::cmp::Reverse(sz0), n0.to_string())
                            });
                    if better {
                        symbol_names.insert(sv, name.to_string());
                        symbol_sizes.insert(sv, (sym.st_size, name.to_string()));
                    }
                    if first_table {
                        dynsym_addrs.insert(sv);
                    }
                }
            }
        }
        arm_map_syms.sort_unstable();
        arm_map_syms.dedup();

        let bin_sh_offset = find_cstr(&data, b"/bin/sh\0");

        // versym 序号 → 版本串（verdef 自身定义 + verneed 引入库版本）
        let version_index = version_map(&elf);
        // objdump 风格带版本符号表（只有 dynsym 参与 symbol versioning）。
        // 同地址多别名的选择按 objdump compare_symbols 排序取第一：
        // GLOBAL > WEAK → st_size 大者优先 → 名字字典序（七组实测全对）。
        let mut alias_rows: Vec<(u64, String, String, bool, u64, usize)> = Vec::new();
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if sym.st_value == 0 {
                continue;
            }
            if sym.st_type() == goblin::elf::sym::STT_SECTION || sym.st_shndx == 0 {
                continue;
            }
            let sv = if is_arm { sym.st_value & !1 } else { sym.st_value };
            let Some(name) = elf.dynstrtab.get_at(sym.st_name) else { continue };
            let vs = elf
                .versym
                .as_ref()
                .and_then(|v| v.get_at(i))
                .map(|v| v.vs_val)
                .unwrap_or(0);
            let annotated = if vs == 0 || (vs & !0x8000) <= 1 {
                // 0=local, 1=global：无版本
                name.to_string()
            } else if let Some(ver) = version_index.get(&(vs & !0x8000)) {
                // 0x8000 位是 hidden 标志：非 hidden → `@@`（default 版本）
                let sep = if vs & 0x8000 != 0 { "@" } else { "@@" };
                format!("{name}{sep}{ver}")
            } else {
                name.to_string()
            };
            alias_rows.push((sv, annotated, name.to_string(), sym.st_bind() == goblin::elf::sym::STB_GLOBAL, sym.st_size, alias_rows.len()));
        }

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
        // EF_MIPS_ARCH = e_flags >> 28：0=mips1 1=mips2 2=mips3 3=mips4 4=mips5
        // 5=mips32 6=mips64 7=mips32r2 8=mips64r2 9=mips32r6 10=mips64r6
        let mips_arch_level = (elf.header.e_flags >> 28) as u8;
        // arm：ISA 边界表（master record_instruction_sets：dynsym STT_FUNC 值的 thumb 位；
        // 排序后只在切换点保留 —— chunk_while 同 ISA 相邻合并，取每段首元素）
        let mut func_isa: Vec<(u64, bool)> = elf
            .dynsyms
            .iter()
            .filter(|s| s.st_value != 0 && s.is_function())
            .map(|s| (s.st_value & !1, s.st_value & 1 == 1))
            .collect();
        func_isa.sort_by_key(|&(a, _)| a);
        let mut arm_isa_chunks: Vec<(u64, bool)> = Vec::new();
        for (addr, thumb) in func_isa {
            if arm_isa_chunks.last().map(|&(_, t)| t) != Some(thumb) {
                arm_isa_chunks.push((addr, thumb));
            } else if arm_isa_chunks.is_empty() {
                arm_isa_chunks.push((addr, thumb));
            }
        }
        // arm：objdump（bfd elf32_arm_get_synthetic_symtab）的 @plt 合成符号。
        // 布局：PLT0(20B) + N×(可选 4B thumb veneer 0x46c04778 + 12B add/add/ldr)。
        // GOT slot 由立即数链推出，与 .rel.plt 的 r_offset 匹配取名。
        if is_arm {
            if let Some(sh) = elf
                .section_headers
                .iter()
                .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".plt"))
            {
                let (base, off, size) = (sh.sh_addr as u64, sh.sh_offset as usize, sh.sh_size as usize);
                if off + size <= data.len() && size > 20 {
                    let bytes = &data[off..off + size];
                    let word = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
                    // .rel.plt：GOT slot → 符号名
                    let mut slot_map = std::collections::HashMap::new();
                    for r in elf.pltrelocs.iter() {
                        if r.r_sym == 0 {
                            continue;
                        }
                        if let Some(sym) = elf.dynsyms.get(r.r_sym) {
                            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                                slot_map.entry(r.r_offset).or_insert_with(|| name.to_string());
                            }
                        }
                    }
                    let mut a = 20usize; // 跳过 PLT0
                    while a + 12 <= size {
                        let entry = a;
                        // thumb veneer：bx pc 后接 nop（旧）或 b .（新链接器）
                        if matches!(word(a), 0x46c0_4778 | 0xe7fd_4778) {
                            a += 4;
                            if a + 12 > size {
                                break;
                            }
                        }
                        let (w1, w2, w3) = (word(a), word(a + 4), word(a + 8));
                        if (w1 & 0xffff_f000) == 0xe28f_c000
                            && (w2 & 0xffff_f000) == 0xe28c_c000
                            && (w3 & 0xffff_0000) == 0xe5bc_0000
                        {
                            let mut ip = base + a as u64 + 8 + arm_expand_imm_c(w1 & 0xfff) as u64;
                            ip += arm_expand_imm_c(w2 & 0xfff) as u64;
                            let slot = ip + (w3 & 0xfff) as u64;
                            if let Some(name) = slot_map.get(&slot) {
                                symbol_names.insert(base + entry as u64, format!("{name}@plt"));
                            }
                        }
                        a += 12;
                    }
                }
            }
        }
        // riscv64：objdump（bfd elf64_riscv_get_synthetic_symtab）的 @plt 合成符号。
        // 布局：PLT0(16B) + N×16B（auipc t3 / ld t3,imm(t3) / jalr t3 / nop）。
        // GOT slot = (auipc 高 20 位 << 12) + pc + (ld 低 12 位)。
        if arch == crate::elf::Arch::Riscv64 {
            if let Some(sh) = elf
                .section_headers
                .iter()
                .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".plt"))
            {
                let (base, off, size) = (sh.sh_addr as u64, sh.sh_offset as usize, sh.sh_size as usize);
                if off + size <= data.len() && size > 16 {
                    let bytes = &data[off..off + size];
                    let word = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
                    let mut slot_map = std::collections::HashMap::new();
                    for r in elf.pltrelocs.iter() {
                        if r.r_sym == 0 {
                            continue;
                        }
                        if let Some(sym) = elf.dynsyms.get(r.r_sym) {
                            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                                slot_map.entry(r.r_offset).or_insert_with(|| name.to_string());
                            }
                        }
                    }
                    let sext20 = |v: u32| -> i64 { (((v << 12) as i32) >> 12) as i64 };
                    let mut a = 16usize; // 跳过 PLT0
                    while a + 16 <= size {
                        let (w1, w2, w3) = (word(a), word(a + 4), word(a + 8));
                        // auipc t3, imm 与 ld t3, imm(t3) 的配对
                        if w1 & 0x7f == 0x17
                            && ((w1 >> 7) & 0x1f) == 28
                            && w2 & 0x7f == 0x03
                            && ((w2 >> 7) & 0x1f) == 28
                            && ((w2 >> 12) & 7) == 3
                            && w3 & 0x7f == 0x67
                        {
                            let hi = sext20(w1 >> 12);
                            let lo = (((w2 >> 20) as i32) << 20) >> 20; // 12 位符号扩展
                            let slot = (base + a as u64).wrapping_add_signed(hi * 0x1000 + lo as i64);
                            if let Some(name) = slot_map.get(&slot) {
                                symbol_names.insert(base + a as u64, format!("{name}@plt"));
                            }
                        }
                        a += 16;
                    }
                }
            }
        }
        let symbols_versioned: std::collections::HashMap<u64, String> = {
            // (非 GLOBAL? -size, 裸名) 排序取第一 —— objdump compare_symbols 原样
            // （裸名排序：带 @@ 版本后缀的串会破坏字典序，如 memset4@@ < memset@@）
            let mut by_addr: std::collections::HashMap<
                u64,
                Vec<(bool, i64, &str, bool, usize, String)>,
            > = std::collections::HashMap::new();
            for (sv, annotated, name, is_global, size, idx) in &alias_rows {
                by_addr.entry(*sv).or_default().push((
                    !*is_global,
                    -(*size as i64),
                    name.as_str(),
                    annotated.contains("@@"),
                    *idx,
                    annotated.clone(),
                ));
            }
            let mut m = std::collections::HashMap::new();
            for (addr, mut rows) in by_addr {
                // 同名同 size 的全平手（同名多版本）：先取**默认版本**（@@，无
                // hidden 位），再取 dynsym 后者。宿主 qsort 不稳定序的实测近似：
                // arm 9 样本与 riscv64 4 样本上均为最优。
                // mips：无 symtab → sorted_syms=dynsym 稳定序（glibc qsort=merge
                // sort），全平手时保表序 → 取 dynsym **首个**（@GLIBC_2.0 早于
                // @@GLIBC_2.2.3 出现）。
                rows.sort_by(|a, b| {
                    (a.0, a.1, a.2)
                        .cmp(&(b.0, b.1, b.2))
                        .then(b.3.cmp(&a.3)) // @@（默认版本）优先于 @（hidden）
                        .then(b.4.cmp(&a.4))
                });
                if is_mips {
                    // 撤销 @@/表序二级排序，回到 compare_symbols 稳定序：全平手
                    // （同名同 size 同 bind）取 dynsym 首个
                    let head = rows[0].clone();
                    let tie_all_same = rows
                        .iter()
                        .all(|r| (r.0, r.1, r.2) == (head.0, head.1, head.2));
                    if tie_all_same {
                        let first = rows.iter().min_by_key(|r| r.4).unwrap();
                        m.insert(addr, first.5.clone());
                        continue;
                    }
                }
                m.insert(addr, rows.remove(0).5);
            }
            m
        };
        let mut symbol_addrs: Vec<u64> = symbol_names.keys().copied().collect();
        symbol_addrs.sort_unstable();
        let arm_sym_starts: Vec<u64> = {
            let mut v: Vec<u64> = elf
                .dynsyms
                .iter()
                .filter(|s| s.st_value != 0 && s.is_function())
                .map(|s| s.st_value & !1)
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        // mips：objdump -d 端点表（dynsym FUNC）+ AX section 序。
        // sh_flags & SHF_EXECINSTR 的 section（.text/.MIPS.stubs/__libc_freeres_fn/…）。
        let mips_func_starts: Vec<u64> = {
            let mut v: Vec<u64> = elf
                .dynsyms
                .iter()
                .filter(|s| s.st_value != 0 && s.is_function())
                .map(|s| s.st_value)
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let mips_code_sections: Vec<(u64, u64)> = {
            let mut v: Vec<(u64, u64)> = elf
                .section_headers
                .iter()
                .filter(|sh| sh.sh_flags as u32 & goblin::elf::section_header::SHF_EXECINSTR != 0)
                .map(|sh| (sh.sh_addr, sh.sh_size))
                .filter(|&(addr, _)| addr != 0)
                .collect();
            v.sort_unstable();
            v
        };
        Ok(Libc { data, segments, arch, mips_el, mips_arch_level,
            symbol_names,
            symbols_versioned,
            symbol_addrs,
            symbols_by_name,
            bin_sh_offset,
            pltgot,
            build_id,
            arm_isa_chunks,
            arm_sym_starts,
            arm_map_syms,
            mips_func_starts,
            mips_code_sections,
            imports_glibc,
        })
    }

    /// 函数名 → libc 偏移（dynsym 精确匹配；未定义/未找到为 None）。
    ///
    /// 对齐 Ruby objdump -T 首行语义：同名多符号取**地址最小**者。
    pub fn function_offset(&self, name: &str) -> Option<u64> {
        self.symbols_by_name.get(name).and_then(|v| v.iter().min().copied())
    }

    /// arm：地址所在的 ISA（master thumb_at?：最后一个 start<=addr 的 chunk 声明的；
    /// 无符号在地址之前时按 thumb —— 文件其余部分 overwhelmingly 是 thumb）。
    pub fn arm_thumb_at(&self, addr: u64) -> bool {
        match self.arm_isa_chunks.partition_point(|&(a, _)| a <= addr) {
            0 => true,
            i => self.arm_isa_chunks[i - 1].1,
        }
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
                // 非 x86（2.1.1 管线）注释走 objdump compare_symbols 语义：
                // 别名组胜者（带版本注解），回落裸名。x86 走 1.10.0 老注释路径。
                let name = if matches!(
                    self.arch,
                    crate::elf::Arch::Arm
                        | crate::elf::Arch::Riscv64
                        | crate::elf::Arch::Aarch64
                        | crate::elf::Arch::Mips
                ) {
                    self.symbols_versioned
                        .get(&a)
                        .or_else(|| self.symbol_names.get(&a))
                        .cloned()
                        .unwrap_or_default()
                } else {
                    self.symbol_names.get(&a).cloned().unwrap_or_default()
                };
                format!("{name}+{:#x}", addr - a)
            }
            None => String::new(),
        }
    }
}

/// A32 立即数旋转展开（PLT stub 的 add ip, #imm 解码用）。
fn arm_expand_imm_c(imm12: u32) -> u32 {
    (imm12 & 0xff).rotate_right(((imm12 >> 8) & 0xf) * 2)
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

