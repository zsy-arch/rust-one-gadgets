//! 全量反汇编：iced-x86 解码 ELF 字节，objdump 风格文本行**按需**渲染。
//!
//! one_gadget 1.10.0 的候选发现与模拟全部基于 objdump 文本：
//! - objdump 命令是 `--dwarf-start=0 --no-show-raw-insn -w -d -M intel`：
//!   **无字节列**、不自动换行 → 每条指令恰好一行
//! - grep 'call.*<exec..>' 依赖 `<sym@@VER>` 符号注释
//! - grep '# <bin_sh_hex>' 依赖 rip 相对目标的 `# <hex> <sym>` 尾注
//! - `branch?` 是整行子串匹配（jmp/je/…，连注释文本都算）
//!
//! 性能关键：全量 disasm 只做**解码**（枚举 + 目标地址，无字符串分配）；
//! `text`/`line` 由 `render_text`/`render_line` 按需重放单条指令生成
//! （候选窗口总共只有几千行，而全量格式化是 51 万行 × 2 次分配）。

use crate::elf::Libc;
use iced_x86::Formatter;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

/// 一条解码后的指令（无文本；渲染走 `render_text`/`render_line`）。
#[derive(Clone, Debug)]
pub struct Insn {
    pub addr: u64,
    /// 下一条指令地址（= 本条 ip + len）。
    pub next_addr: u64,
    pub mnemonic: Mnemonic,
    /// 条件/无条件直接跳转目标。
    pub branch_target: Option<u64>,
    /// call 直接目标（call rel32）。
    pub call_target: Option<u64>,
    /// rip 相对内存操作数的目标虚拟地址。
    pub rip_target: Option<u64>,
}

impl Insn {
    /// 操作数部分（`lea rbp,[rsp+0x220]`）——模拟器消费的文本。
    ///
    /// 从 libc 字节重放解码这一条指令再格式化（仅候选路径调用，量小）。
    pub fn render_text(&self, libc: &Libc) -> String {
        let len = (self.next_addr - self.addr) as usize;
        let Some(bytes) = libc.bytes_at_vaddr(self.addr, len) else {
            return String::new();
        };
        // x86 管线只服务 X64/X86；新架构走 search21（textgen）
        let bits = match libc.arch {
            crate::elf::Arch::X64 => 64,
            _ => 32,
        };
        let mut decoder = Decoder::with_ip(bits, bytes, self.addr, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        if !decoder.can_decode() {
            return String::new();
        }
        decoder.decode_out(&mut ins);
        format_insn_text(&ins, libc)
    }

    /// 完整 objdump 行（已 strip）：`50a29:\tlea rax,[rip+0x187c65]  # ...`。
    pub fn render_line(&self, libc: &Libc) -> String {
        format!("{:x}:\t{}", self.addr, self.render_text(libc))
    }
}

/// 把一条已解码指令渲染成 objdump -M intel 风格操作数文本。
///
/// - 直接 call/jmp：`call <hex> <sym>`（无 0x 前缀，objdump 习惯）
/// - rip 相对内存：追加 `        # <hex> <sym>` 尾注
fn format_insn_text(ins: &Instruction, libc: &Libc) -> String {
    // objdump -M intel 风格：0x 前缀 hex、rip 相对、显式内存尺寸
    let mut formatter = iced_x86::IntelFormatter::new();
    {
        let o = formatter.options_mut();
        o.set_hex_prefix("0x");
        o.set_hex_suffix("");
        o.set_uppercase_hex(false);
        o.set_rip_relative_addresses(true);
        o.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
        o.set_leading_zeros(false);
        o.set_branch_leading_zeros(false);
        o.set_hex_digit_group_size(0);
    }
    let mut buf = String::with_capacity(64);
    formatter.format(ins, &mut buf);
    let branch_target = direct_branch_target(ins);
    let call_target = direct_call_target(ins);
    let rip_target = rip_relative_target(ins);
    if let Some(t) = call_target {
        format!("call {:x} <{}>", t, libc.nearest_symbol(t))
    } else if ins.mnemonic() == Mnemonic::Jmp && branch_target.is_some() {
        format!("jmp {:x} <{}>", branch_target.unwrap(), libc.nearest_symbol(branch_target.unwrap()))
    } else if let Some(t) = rip_target {
        buf.push_str(&format!("        # {:x} <{}>", t, libc.nearest_symbol(t)));
        buf
    } else {
        buf
    }
}

/// 反汇编 [lo, hi) 虚拟地址区间（须在可执行段内）——只解码，不格式化。
pub fn disassemble_range(libc: &Libc, lo: u64, hi: u64) -> Vec<Insn> {
    let mut insns = Vec::new();
    let Some(seg) = libc.executable_segment() else {
        return insns;
    };
    let lo = lo.max(seg.vaddr);
    let hi = hi.min(seg.vaddr + seg.file_size);
    if lo >= hi {
        return insns;
    }
    let start_off = libc.vaddr_to_off(lo).unwrap_or(seg.file_off) as usize;
    let end_off =
        libc.vaddr_to_off(hi - 1).map(|o| o + 1).unwrap_or(seg.file_off + seg.file_size) as usize;
    let bytes = &libc.data[start_off..end_off];

    let bits = match libc.arch {
        crate::elf::Arch::X64 => 64,
        _ => 32,
    };
    let mut decoder = Decoder::with_ip(bits, bytes, lo, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut ins);
        let addr = ins.ip();
        if addr >= hi {
            break;
        }
        insns.push(Insn {
            addr,
            next_addr: ins.next_ip(),
            mnemonic: ins.mnemonic(),
            branch_target: direct_branch_target(&ins),
            call_target: direct_call_target(&ins),
            rip_target: rip_relative_target(&ins),
        });
    }
    insns
}

/// Jcc / JMP 的直接目标（rel 近跳）。
fn direct_branch_target(ins: &Instruction) -> Option<u64> {
    match ins.mnemonic() {
        Mnemonic::Jmp => {
            if op_kind_is(ins, OpKind::NearBranch64) || op_kind_is(ins, OpKind::NearBranch32) {
                Some(ins.near_branch_target())
            } else {
                None
            }
        }
        m if is_jcc(m) || is_jcxz(m) => Some(ins.near_branch_target()),
        _ => None,
    }
}

/// 指令任一操作数是否为 `kind`。
fn op_kind_is(ins: &Instruction, kind: OpKind) -> bool {
    ins.op_kinds().any(|k| k == kind)
}

/// call 的直接目标（call rel32）。
fn direct_call_target(ins: &Instruction) -> Option<u64> {
    // NearBranch64（amd64 rel32/rel2）或 NearBranch32（i386 rel32）
    if ins.mnemonic() == Mnemonic::Call
        && (op_kind_is(ins, OpKind::NearBranch64) || op_kind_is(ins, OpKind::NearBranch32))
    {
        Some(ins.near_branch_target())
    } else {
        None
    }
}

/// rip 相对内存操作数的目标虚拟地址。
fn rip_relative_target(ins: &Instruction) -> Option<u64> {
    for i in 0..ins.op_count() {
        if ins.op_kind(i) == OpKind::Memory && ins.memory_base() == Register::RIP {
            return Some(ins.memory_displacement64());
        }
    }
    None
}

/// 全部 Jcc 助记符判定。
fn is_jcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
    )
}

/// jcxz/jecxz/jrcxz。
fn is_jcxz(m: Mnemonic) -> bool {
    matches!(m, Mnemonic::Jrcxz | Mnemonic::Jecxz | Mnemonic::Jcxz)
}

/// 指令文本 → (助记符, 操作数列表)。
/// 对齐 1.10.0 `Instruction#fetch_args`：`#`/`//` 截断 + 括号深度感知逗号分割
/// + 尺寸前缀剥离（XMMWORD/QWORD/DWORD/WORD/BYTE/PTR，大小写均处理）。
pub fn split_mnemonic_operands(text: &str) -> Option<(&str, Vec<String>)> {
    // objdump 注释截断（rindex('#') 语义：最后一个 #）
    let cut = text.rfind('#').unwrap_or(text.len());
    let t = text[..cut].trim();
    let (mnem, rest) = t.split_once(' ')?;
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in rest.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                args.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        args.push(cur);
    }
    let args: Vec<String> = args
        .into_iter()
        .map(|a| strip_size_prefix(&a))
        .filter(|a| !a.is_empty())
        .collect();
    Some((mnem, args))
}

/// objdump/iced 的尺寸前缀剥离（Ruby: gsub(/XMMWORD|QWORD|DWORD|WORD|BYTE|PTR/, '')）。
fn strip_size_prefix(a: &str) -> String {
    // 顺序敏感：XMMWORD 先于 WORD（否则残留 XMM）
    const TOKENS: [&str; 12] = [
        "XMMWORD", "xmmword", "QWORD", "qword", "DWORD", "dword", "WORD", "word", "BYTE", "byte",
        "PTR", "ptr",
    ];
    let mut s = a.trim().to_string();
    for t in TOKENS {
        if s.contains(t) {
            // 只剥离独立 token（前后有边界）——简单起见按空格分词重组
            s = s
                .split_whitespace()
                .filter(|w| !TOKENS.contains(w))
                .collect::<Vec<_>>()
                .join(" ");
        }
    }
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_basic_block() {
        // 50            push rax
        // 48 31 c0      xor rax, rax
        // 74 05         je +5
        // b8 01000000   mov eax, 1
        // e8 00000000   call next (rel=0)
        // c3            ret
        let code: Vec<u8> = vec![
            0x50, 0x48, 0x31, 0xc0, 0x74, 0x05, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00,
            0x00, 0x00, 0xc3,
        ];
        let mut decoder = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        let mut targets = vec![];
        while decoder.can_decode() {
            decoder.decode_out(&mut ins);
            targets.push(direct_branch_target(&ins));
        }
        assert_eq!(targets.len(), 6);
        // je 在 0x1004（2 字节），next=0x1006，目标 = 0x1006+5 = 0x100b
        assert_eq!(targets[2], Some(0x100b));
        assert_eq!(targets[3], None); // mov
    }

    #[test]
    fn test_split_mnemonic_operands() {
        let (m, a) = split_mnemonic_operands("mov QWORD PTR [rsp+0x78],0x0").unwrap();
        assert_eq!(m, "mov");
        assert_eq!(a, vec!["[rsp+0x78]", "0x0"]);
        // 注释截断
        let (m2, a2) =
            split_mnemonic_operands("lea rax,[rip+0x187c65]        # 1d8695 <sym+0x18b>").unwrap();
        assert_eq!(m2, "lea");
        assert_eq!(a2, vec!["rax", "[rip+0x187c65]"]);
        // 小写尺寸前缀
        let (_, a3) = split_mnemonic_operands("mov qword ptr [rsp+0x78],0").unwrap();
        assert_eq!(a3, vec!["[rsp+0x78]", "0"]);
    }
}
