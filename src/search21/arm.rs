//! arm 的 ArchSearch 实现（master fetchers/arm.rb）。

use super::{ArchSearch, SearchCtx, COND, TERM, UNCOND};
use crate::elf::Libc;
use crate::emulator21::processor::{mnemonic_of, EmuError, State};
use crate::emulator21::Val;
use std::collections::HashSet;

/// 条件码（fetchers/arm.rb#CONDS —— 含 vs/vc）。
const CONDS: &[&str] = &[
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
];

pub struct ArmSearch;

/// 行内首个 hex 地址。
fn line_addr(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let end = s.find(':')?;
    if end == 0 || !s[..end].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(&s[..end], 16).ok()
}

/// 分支目标：`<...>` 尾注前的最后一个 hex token。
fn target_of(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let after_colon = match s.find(':') {
        Some(c) if s[..c].chars().all(|x| x.is_ascii_hexdigit()) && !s[..c].is_empty() => {
            s[c + 1..].trim_start()
        }
        _ => s,
    };
    let body = after_colon.split(" <").next().unwrap_or(after_colon);
    let last = body.split_whitespace().last()?;
    let tok: String = last.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (!tok.is_empty()).then(|| u64::from_str_radix(&tok, 16).unwrap_or(0))
}

/// REG = /r\d+|sl|fp|ip|lr/
fn is_reg(tok: &str) -> bool {
    matches!(tok, "sl" | "fp" | "ip" | "lr")
        || (tok.starts_with('r') && tok.len() >= 2 && tok[1..].chars().all(|c| c.is_ascii_digit()))
}

/// `[rB, rX]` 的基址寄存器（含所有出现）。
fn reg_offset_bases(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(close) = line[i + 1..].find(']') {
                let inner = &line[i + 1..i + 1 + close];
                let parts: Vec<&str> = inner.split(',').map(|p| p.trim()).collect();
                if parts.len() == 2 && is_reg(parts[0]) && is_reg(parts[1]) {
                    out.push(parts[0].to_string());
                }
                i += close + 1;
            }
        }
        i += 1;
    }
    out
}

/// `:\s*add(?:\.w)?\s+reg, pc` 行判定（行内唯一 add）。
fn is_got_add(line: &str, reg: &str) -> bool {
    let Some(addr_end) = line.find(':') else { return false };
    let body = line[addr_end + 1..].trim_start();
    let Some((mnem, rest)) = body.split_once(char::is_whitespace) else { return false };
    if mnem != "add" && mnem != "add.w" {
        return false;
    }
    let ops: Vec<&str> = rest.split(',').map(|p| p.trim()).collect();
    ops.len() == 2 && ops[0] == reg && ops[1] == "pc"
}

/// `:\s*ldr(?:\.w)?\s+reg, \[pc` 行判定。
fn is_got_ldr(line: &str, reg: &str) -> bool {
    let Some(addr_end) = line.find(':') else { return false };
    let body = line[addr_end + 1..].trim_start();
    let Some((mnem, rest)) = body.split_once(char::is_whitespace) else { return false };
    if mnem != "ldr" && mnem != "ldr.w" {
        return false;
    }
    let Some((first, second)) = rest.split_once(',') else { return false };
    first.trim() == reg && (second.trim().starts_with("[pc") || second.trim() == "[pc")
}

/// window_establishes?：首个 `[reg, rX]` 使用之前窗口内已有 `add reg, pc`。
fn window_establishes(reg: &str, cmds: &[String]) -> bool {
    let Some(use_at) = cmds
        .iter()
        .position(|c| reg_offset_bases(c).iter().any(|b| b == reg))
    else {
        return false;
    };
    cmds[..use_at].iter().any(|c| is_got_add(c, reg))
}

/// 向后可达的最早行号（窗口起点截断）。
fn reachable_from(ctx: &SearchCtx, pos: usize, reach: usize) -> usize {
    let floor = pos.saturating_sub(reach);
    ((floor)..=pos).rev().find(|i| ctx.window_starts.contains(i)).unwrap_or(floor)
}

/// find_got_setup_lines：从 pos 回扫找 `ldr reg, [pc…]; add reg, pc` 对。
fn find_got_setup_lines(ctx: &SearchCtx, reg: &str, before: u64) -> Option<(String, String)> {
    let pos = *ctx.index.get(&before)?;
    let lines = ctx.lines;
    let setup_reach = 400usize;
    let load_reach = 4usize;
    let add_at = (reachable_from(ctx, pos, setup_reach)..=pos)
        .rev()
        .find(|&i| is_got_add(&lines[i], reg))?;
    let ldr_at = (reachable_from(ctx, add_at, load_reach)..=add_at)
        .rev()
        .find(|&i| is_got_ldr(&lines[i], reg))?;
    Some((lines[ldr_at].clone(), lines[add_at].clone()))
}

impl ArchSearch for ArmSearch {
    fn branch_kind(&self, line: &str) -> Option<(u8, u64)> {
        let m = mnemonic_of(line);
        let m = m.strip_suffix(".w").or_else(|| m.strip_suffix(".n")).unwrap_or(m);
        // conditional：cbz/cbnz 或 b<cond>
        if matches!(m, "cbz" | "cbnz") {
            return Some((COND, target_of(line)?));
        }
        if !m.starts_with("bl") && m.starts_with('b') && CONDS.contains(&&m[1..]) {
            return Some((COND, target_of(line)?));
        }
        if m == "b" {
            return Some((UNCOND, target_of(line)?));
        }
        if m.starts_with("bx") || matches!(m, "tbb" | "tbh") {
            return Some((TERM, 0));
        }
        if matches!(m, "pop" | "ldm" | "ldmia" | "ldmfd" | "ldmdb") && line.contains(" pc") {
            return Some((TERM, 0));
        }
        // `:\s*(mov|ldr)(\.[wn])?\s+pc\b`
        if let Some(addr_end) = line.find(':') {
            let body = line[addr_end + 1..].trim_start();
            let Some((mnem, rest)) = body.split_once(char::is_whitespace) else {
                return None;
            };
            let base = mnem.strip_suffix(".w").or_else(|| mnem.strip_suffix(".n")).unwrap_or(mnem);
            let rest = rest.trim_start();
            let pc_first = rest.starts_with("pc,") || rest.starts_with("pc ") || rest == "pc";
            if (base == "mov" || base == "ldr") && pc_first {
                return Some((TERM, 0));
            }
        }
        None
    }

    fn call_addr(&self, line: &str) -> Option<String> {
        let m = mnemonic_of(line);
        let m = m.strip_suffix(".w").or_else(|| m.strip_suffix(".n")).unwrap_or(m);
        if m != "bl" && m != "blx" {
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

    /// 分块反汇编：窗口内按 ISA 边界切（master decode_ranges）。
    fn disasm(&self, libc: &Libc, lo: u64, hi: u64) -> Vec<String> {
        let mut bounds: Vec<u64> = vec![lo];
        for &(a, _) in &libc.arm_isa_chunks {
            if a > lo && a < hi {
                bounds.push(a);
            }
        }
        bounds.push(hi);
        let mut out = Vec::new();
        for pair in bounds.windows(2) {
            out.extend(
                crate::textgen::arm::disassemble_range(libc, pair[0], pair[1])
                    .into_iter()
                    .map(|l| l.text),
            );
        }
        out
    }

    /// thumb BL（半字扫描）+ A32 BL（字对齐）。
    fn scan_calls(&self, libc: &Libc, targets: &HashSet<u64>) -> Option<Vec<u64>> {
        let seg = libc.executable_segment()?;
        let base = seg.vaddr;
        let data = &libc.data[seg.file_off as usize..(seg.file_off + seg.file_size) as usize];
        let halves: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut sites: Vec<u64> = Vec::new();
        for i in 0..halves.len() {
            let high = halves[i];
            // thumb BL：hw0 ∈ [0xf000,0xf7ff]，hw1 高半 0xd
            if (0xf000..=0xf7ff).contains(&high) {
                if let Some(&low) = halves.get(i + 1) {
                    if low & 0xd000 == 0xd000 {
                        let addr = base + (i as u64) * 2;
                        let t = thumb_bl_target(addr, high, low) & !1;
                        if targets.contains(&t) {
                            sites.push(addr);
                        }
                    }
                }
            }
            if i % 2 == 0 {
                let Some(&low) = halves.get(i + 1) else { continue };
                // A32 BL：word bits 27:24 == 1011
                if (low >> 8) & 0x0f == 0x0b {
                    let addr = base + (i as u64) * 2;
                    let word = (high as u32) | ((low as u32) << 16);
                    if targets.contains(&a32_bl_target(addr, word)) {
                        sites.push(addr);
                    }
                }
            }
        }
        sites.sort_unstable();
        sites.dedup();
        Some(sites)
    }

    fn new_state(&self) -> State {
        crate::emulator21::arm::new_state()
    }

    fn begin(&self, libc: &Libc) {
        crate::emulator21::arm::set_file(std::rc::Rc::new(libc.data.clone()));
    }

    fn process(&self, st: &mut State, line: &str) -> bool {
        match crate::emulator21::arm::process_line(st, line) {
            Ok(()) => true,
            Err(EmuError::UnsupportedInstruction(m)) => {
                st.refused_line = Some(m);
                false
            }
            Err(EmuError::UnsupportedInstructionArgument(m)) if m == "__terminal__" => true,
            Err(_) => false,
        }
    }

    fn prepare(&self, st: &mut State, ctx: &SearchCtx, lines: &[String]) -> Vec<String> {
        crate::emulator21::arm::note_instruction_set(st, lines);
        // seed_got_registers
        let Some(start) = lines.first().and_then(|l| line_addr(l)) else {
            return Vec::new();
        };
        // 候选用到的 [rB, rX] 基址寄存器（去重，保持出现序）
        let mut regs: Vec<String> = Vec::new();
        for c in lines {
            for b in reg_offset_bases(c) {
                if !regs.contains(&b) {
                    regs.push(b);
                }
            }
        }
        let mut seeded = Vec::new();
        for reg in regs {
            if window_establishes(&reg, lines) {
                continue;
            }
            if let Some((ldr_line, add_line)) = find_got_setup_lines(ctx, &reg, start) {
                if crate::emulator21::arm::process_line(st, &ldr_line).is_ok()
                    && crate::emulator21::arm::process_line(st, &add_line).is_ok()
                {
                    seeded.push(reg);
                }
            }
        }
        seeded
    }

    fn fixup(&self, _st: &State, gots: &[String], constraints: &mut Vec<String>) {
        if gots.is_empty() {
            return;
        }
        for reg in gots {
            let c = format!("{reg} is the GOT address of libc");
            if !constraints.contains(&c) {
                constraints.insert(0, c);
            }
        }
        let gots: HashSet<&str> = gots.iter().map(|s| s.as_str()).collect();
        constraints.retain(|c| {
            !gots.iter().any(|r| c == &format!("writable: {r}"))
        });
    }
}

/// thumb BL 目标（fetchers/arm.rb#thumb_bl_target）。
fn thumb_bl_target(addr: u64, high: u16, low: u16) -> u64 {
    let s = ((high >> 10) & 1) as u64;
    let i1 = (!( ((low >> 13) & 1) as u64 ^ s )) & 1;
    let i2 = (!( ((low >> 11) & 1) as u64 ^ s )) & 1;
    let mut imm = (s << 24)
        | (i1 << 23)
        | (i2 << 22)
        | (((high & 0x3ff) as u64) << 12)
        | (((low & 0x7ff) as u64) << 1);
    if s == 1 {
        imm -= 1 << 25;
    }
    addr.wrapping_add(4).wrapping_add(imm) & 0xffff_ffff
}

/// A32 BL 目标。
fn a32_bl_target(addr: u64, word: u32) -> u64 {
    let mut imm = ((word & 0xff_ffff) as u64) << 2;
    if imm & (1 << 25) != 0 {
        imm -= 1 << 26;
    }
    addr.wrapping_add(8).wrapping_add(imm) & 0xffff_ffff
}

#[allow(dead_code)]
fn _unused_val(v: Val) -> Val {
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_kind() {
        let a = ArmSearch;
        assert_eq!(a.branch_kind("4a1c0: b 4a200"), Some((UNCOND, 0x4a200)));
        assert_eq!(a.branch_kind("4a1c0: bne 4a200 <x>"), Some((COND, 0x4a200)));
        assert_eq!(a.branch_kind("4a1c0: bne.w 4a200"), Some((COND, 0x4a200)));
        assert_eq!(a.branch_kind("2c23a: cbz r7, 2c23e <x+0x36>"), Some((COND, 0x2c23e)));
        assert_eq!(a.branch_kind("4a1c0: bl 73ba0 <x>"), None);
        assert_eq!(a.branch_kind("4a1c0: blx 73ba0 <x>"), None);
        assert_eq!(a.branch_kind("2cb6c: bx lr"), Some((TERM, 0)));
        assert_eq!(a.branch_kind("2c240: pop {r4, r5, r6, r7, pc}"), Some((TERM, 0)));
        assert_eq!(a.branch_kind("2c2fc: ldmia r1, {r0, r1}"), None);
        assert_eq!(a.branch_kind("4a1c0: mov pc, r3"), Some((TERM, 0)));
        assert_eq!(a.branch_kind("4a1c0: mov.w pc, r3"), Some((TERM, 0)));
        assert_eq!(a.branch_kind("4a1c0: nop"), None);
    }

    #[test]
    fn test_call_addr() {
        let a = ArmSearch;
        assert_eq!(
            a.call_addr("3980c:\tbl 498bc <__woverflow@@GLIBC_2.4>"),
            Some("498bc <__woverflow@@GLIBC_2.4>".to_string())
        );
        assert_eq!(a.call_addr("2bf86:\tblx\t15f54 <free@plt+0x14>"), Some("15f54 <free@plt+0x14>".to_string()));
        assert_eq!(a.call_addr("1000: bne 4a200"), None);
    }

    #[test]
    fn test_thumb_bl_target() {
        // 高 0xf004 低 0xfdd3 → brew 实测 bl 30b30（2bf86 处）
        assert_eq!(thumb_bl_target(0x2bf86, 0xf004, 0xfdd3), 0x30b30);
    }

    #[test]
    fn test_reg_offset_bases() {
        assert_eq!(reg_offset_bases("88ab2: ldr r2, [r1, r2]"), vec!["r1".to_string()]);
        assert_eq!(reg_offset_bases("0: ldr r2, [r1, #8]"), Vec::<String>::new());
    }
}
