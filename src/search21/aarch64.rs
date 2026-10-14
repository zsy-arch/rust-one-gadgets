//! aarch64 的 ArchSearch 实现（master fetchers/aarch64.rb）。

use super::{ArchSearch, COND, TERM, UNCOND};
use crate::elf::Libc;
use crate::emulator21::processor::{mnemonic_of, EmuError, State};
use std::collections::HashSet;

/// b.<cond> 条件码表。
const CONDS: &[&str] = &[
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
];

pub struct Aarch64Search;

/// 行内最后一个 hex 操作数（分支目标；cbz/tbz 的目标在寄存器/位号之后）。
fn target_of(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let after_colon = match s.find(':') {
        Some(c) if s[..c].chars().all(|x| x.is_ascii_hexdigit()) && !s[..c].is_empty() => {
            s[c + 1..].trim_start()
        }
        _ => s,
    };
    // 去掉 `<sym>` 尾注后取最后一个 token
    let body = after_colon.split(" <").next().unwrap_or(after_colon);
    let last = body.split_whitespace().last()?;
    let tok: String = last.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (!tok.is_empty()).then(|| u64::from_str_radix(&tok, 16).unwrap_or(0))
}

impl ArchSearch for Aarch64Search {
    fn branch_kind(&self, line: &str) -> Option<(u8, u64)> {
        let m = mnemonic_of(line);
        let cond = ["cbz", "cbnz", "tbz", "tbnz"].contains(&m)
            || (m.starts_with("b.") && CONDS.contains(&&m[2..]));
        if cond {
            return Some((COND, target_of(line)?));
        }
        if m == "b" || m == "b.al" {
            return Some((UNCOND, target_of(line)?));
        }
        if ["ret", "br", "braa", "brab", "braaz", "brabz"].contains(&m) {
            return Some((TERM, 0));
        }
        None
    }

    fn call_addr(&self, line: &str) -> Option<String> {
        let m = mnemonic_of(line);
        if m != "bl" {
            return None;
        }
        // 目标文本（到 `<...>` 尾注结束或行尾）
        let s = line.trim_start();
        let after_colon = match s.find(':') {
            Some(c) if s[..c].chars().all(|x| x.is_ascii_hexdigit()) && !s[..c].is_empty() => {
                s[c + 1..].trim_start()
            }
            _ => s,
        };
        let (_mnem, rest) = after_colon.split_once(char::is_whitespace)?;
        // `631e0 <execve>` → 保留地址 + 符号尾注（terminal_call_line 判定用）
        let rest = rest.trim();
        let mut out = String::new();
        for (i, tok) in rest.split_whitespace().enumerate() {
            if i > 0 && tok.starts_with('<') {
                out.push(' ');
                out.push_str(tok);
            } else if i == 0 {
                out.push_str(tok);
            }
        }
        Some(out)
    }

    fn disasm(&self, libc: &Libc, lo: u64, hi: u64) -> Vec<String> {
        crate::textgen::aarch64::disassemble_range(libc, lo, hi)
    }

    /// BL imm26 扫描（master scan_calls）。
    fn scan_calls(&self, libc: &Libc, targets: &HashSet<u64>) -> Option<Vec<u64>> {
        let seg = libc.executable_segment()?;
        let base = seg.vaddr;
        let data = &libc.data[seg.file_off as usize..(seg.file_off + seg.file_size) as usize];
        let mut sites = Vec::new();
        for (i, chunk) in data.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if word & 0xfc00_0000 != 0x9400_0000 {
                continue;
            }
            let mut imm = (word & 0x03ff_ffff) as i64;
            if imm & (1 << 25) != 0 {
                imm -= 1 << 26;
            }
            let addr = base + (i as u64) * 4;
            if targets.contains(&(addr.wrapping_add((imm as u64).wrapping_mul(4)))) {
                sites.push(addr);
            }
        }
        Some(sites)
    }

    fn new_state(&self) -> State {
        crate::emulator21::aarch64::new_state()
    }

    fn process(&self, st: &mut State, line: &str) -> bool {
        match crate::emulator21::aarch64::process_line(st, line) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_kind() {
        let a = Aarch64Search;
        assert_eq!(a.branch_kind("4a1d0: b.ne 4a200 <foo>"), Some((COND, 0x4a200)));
        assert_eq!(a.branch_kind("1000: cbz x0, 9cecc"), Some((COND, 0x9cecc)));
        assert_eq!(a.branch_kind("1000: b 4a200"), Some((UNCOND, 0x4a200)));
        assert_eq!(a.branch_kind("1000: ret"), Some((TERM, 0)));
        assert_eq!(a.branch_kind("1000: nop"), None);
        assert_eq!(a.branch_kind("1000: bl 3f288 <execve>"), None);
    }

    #[test]
    fn test_call_addr() {
        let a = Aarch64Search;
        assert_eq!(
            a.call_addr("3f288: bl 631e0 <execve>"),
            Some("631e0 <execve>".to_string())
        );
        assert_eq!(a.call_addr("1000: b.ne 4a200"), None);
        assert_eq!(a.call_addr("1000: nop"), None);
    }
}
