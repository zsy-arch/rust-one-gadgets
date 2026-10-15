//! riscv64 的 ArchSearch 实现（master fetchers/riscv64.rb）。

use super::{ArchSearch, COND, TERM, UNCOND};
use crate::elf::Libc;
use crate::emulator21::processor::{mnemonic_of, EmuError, State};
use std::collections::HashSet;

pub struct Riscv64Search;

/// COND 表（fetchers/riscv64.rb 无独立表——mnemonic 以 b 开头即 conditional）。
fn cond_relation(mnem: &str) -> Option<&'static str> {
    Some(match mnem {
        "beq" => "eq",
        "bne" => "ne",
        "blt" => "slt",
        "bge" => "sge",
        "bltu" => "ult",
        "bgeu" => "uge",
        "bgt" => "sgt",
        "ble" => "sle",
        "bgtu" => "ugt",
        "bleu" => "ule",
        "beqz" => "eq",
        "bnez" => "ne",
        "bltz" => "slt",
        "bgez" => "sge",
        "blez" => "sle",
        "bgtz" => "sgt",
        _ => return None,
    })
}

/// 行内分支目标（master branch_target：剥地址+助记符后，匹配后跟 `<` 或行尾的
/// hex 词——寄存器操作数因尾随逗号不会命中，目标总在 `<sym>` 前或行尾）。
fn target_of(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let after_colon = match s.find(':') {
        Some(c) if s[..c].chars().all(|x| x.is_ascii_hexdigit()) && !s[..c].is_empty() => {
            s[c + 1..].trim_start()
        }
        _ => s,
    };
    // 剥助记符
    let rest = after_colon.split_once(char::is_whitespace).map(|(_, r)| r).unwrap_or("");
    let rest = rest.split('#').next().unwrap_or(rest);
    // 找「后跟 < 或行尾」的 hex 词（按逗号/空白分界）
    let mut best: Option<&str> = None;
    for tok in rest.split(|c: char| c == ',' || c.is_whitespace()) {
        if tok.is_empty() || !tok.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        best = Some(tok); // 取最后一个满足形态的（目标在行尾/< 前）
    }
    best.and_then(|t| u64::from_str_radix(t, 16).ok())
}

impl ArchSearch for Riscv64Search {
    /// branch_kind（fetchers/riscv64.rb）：
    /// b* → conditional、j → unconditional、ret/jr/jalr → terminator。
    fn branch_kind(&self, line: &str) -> Option<(u8, u64)> {
        let m = mnemonic_of(line);
        if cond_relation(m).is_some() {
            return Some((COND, target_of(line)?));
        }
        if m == "j" {
            return Some((UNCOND, target_of(line)?));
        }
        if matches!(m, "ret" | "jr" | "jalr") {
            return Some((TERM, 0));
        }
        None
    }

    /// call_str = 'jal'：目标文本（含 `<name>` 尾注）。
    fn call_addr(&self, line: &str) -> Option<String> {
        let m = mnemonic_of(line);
        if m != "jal" {
            return None;
        }
        let s = line.trim_start();
        let after_colon = match s.find(':') {
            Some(c) if s[..c].chars().all(|x| x.is_ascii_hexdigit()) && !s[..c].is_empty() => {
                s[c + 1..].trim_start()
            }
            _ => s,
        };
        let (_mnem, rest) = after_colon.split_once(char::is_whitespace)?;
        let rest = rest.split('#').next().unwrap_or(rest).trim();
        // `jal ra,6c286 <_IO_wfile_xsputn@@GLIBC_2.27+0x150>` → 目标 = 最后地址 + <name>
        let mut out = String::new();
        for (i, tok) in rest.split_whitespace().enumerate() {
            if i > 0 && tok.starts_with('<') {
                out.push(' ');
                out.push_str(tok);
            } else if i > 0 {
                // 中间是 ra 等 —— 目标取最后的地址 token，跳过
                continue;
            } else {
                out.push_str(tok);
            }
        }
        Some(out)
    }

    fn disasm(&self, libc: &Libc, lo: u64, hi: u64) -> Vec<String> {
        crate::textgen::riscv64::disassemble_range(libc, lo, hi)
    }

    /// scan_calls：每 2 字节读半字，(low & 0x7f) == 0x6f 判 jal 候选；
    /// jal 位散布 [20|10:1|11|19:12] 重组目标。
    fn scan_calls(&self, libc: &Libc, targets: &HashSet<u64>) -> Option<Vec<u64>> {
        let seg = libc.executable_segment()?;
        let base = seg.vaddr;
        let data = &libc.data[seg.file_off as usize..(seg.file_off + seg.file_size) as usize];
        let mut sites = Vec::new();
        let halves = data.chunks_exact(2);
        let mut idx = 0usize;
        for chunk in halves {
            let low = u16::from_le_bytes([chunk[0], chunk[1]]);
            if (low & 0x7f) != 0x6f {
                idx += 1;
                continue;
            }
            // 高半字可能越界（末尾）：break
            let off = (idx + 1) * 2;
            if off >= data.len() {
                break;
            }
            let high = u16::from_le_bytes([data[off], data[off + 1]]);
            let word = (low as u32) | ((high as u32) << 16);
            let addr = base + (idx as u64) * 2;
            let target = addr.wrapping_add(jal_offset(word) as u64);
            if targets.contains(&target) {
                sites.push(addr);
            }
            idx += 1;
        }
        Some(sites)
    }

    fn new_state(&self) -> State {
        crate::emulator21::riscv64::new_state()
    }

    fn process(&self, st: &mut State, line: &str) -> bool {
        match crate::emulator21::riscv64::process_line(st, line) {
            Ok(()) => true,
            Err(EmuError::UnsupportedInstruction(m)) => {
                st.refused_line = Some(m);
                false
            }
            Err(EmuError::UnsupportedInstructionArgument(m)) if m == "__terminal__" => {
                // reach_terminal_call：成功到达终端 call
                true
            }
            Err(_) => false,
        }
    }
}

/// jal 偏移位散布重组：[20|10:1|11|19:12]（符号扩展 21 位）。
fn jal_offset(word: u32) -> i64 {
    let imm = (((word >> 31) & 0x1) << 20)
        | (((word >> 12) & 0xff) << 12)
        | (((word >> 20) & 0x1) << 11)
        | (((word >> 21) & 0x3ff) << 1);
    if imm & (1 << 20) != 0 {
        (imm as i64) - (1 << 21)
    } else {
        imm as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jal_offset() {
        // jal ra,6c286 型：手算一例（0x6c286-0x688c6=0x39c0 → imm=0x39c0）
        // 编码 word 由 imm 反推：imm[20]=0, imm[10:1]=0x1ce, imm[11]=1, imm[19:12]=0
        let imm = 0x39c0u32;
        let word = (((imm >> 20) & 1) << 31)
            | (((imm >> 1) & 0x3ff) << 21)
            | (((imm >> 11) & 1) << 20)
            | (((imm >> 12) & 0xff) << 12)
            | 0x6f;
        assert_eq!(jal_offset(word), 0x39c0);
        // 负偏移
        let imm = (-0x10i64) as u32; // 位模式
        let word = (((imm >> 20) & 1) << 31)
            | (((imm >> 1) & 0x3ff) << 21)
            | (((imm >> 11) & 1) << 20)
            | (((imm >> 12) & 0xff) << 12)
            | 0x6f;
        assert_eq!(jal_offset(word), -0x10);
    }

    #[test]
    fn test_branch_kind() {
        let s = Riscv64Search;
        assert_eq!(s.branch_kind("4a158:\tbeqz\ta5,4a15e <x>"), Some((COND, 0x4a15e)));
        assert_eq!(s.branch_kind("0:\tj\t4a100 <x>"), Some((UNCOND, 0x4a100)));
        assert_eq!(s.branch_kind("0:\tret"), Some((TERM, 0)));
        assert_eq!(s.branch_kind("0:\tjalr\tra"), Some((TERM, 0)));
        assert_eq!(s.branch_kind("0:\tadd\ta5,a5,a4"), None);
    }
}













