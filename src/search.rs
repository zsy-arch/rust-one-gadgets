//! 搜索流水线：对齐 one_gadget **v1.10.0** `Fetchers::Amd64`。
//!
//! 1.10.0 的候选发现全部基于 objdump 文本（这里用 `Insn::render_line`）：
//! - candidates：全量反汇编里所有匹配 `call.*<(exec[^+]*|posix_spawn[^+]*)>$`
//!   的行，各带前 30 行上下文（grep -B30 的 `--` 分块语义）；
//!   块内再按「第一个匹配 call」切块（连续 call 逐块产出）；
//!   再 slice_prefix（裁到最后分支行之后）；
//!   **最后**才做 amd64 过滤（整块文本 `include?`）。
//! - 过滤：含字面 `posix_spawn@` 直通；否则须含 bin_sh hex 且末行含 `execve`。
//! - jmp_case：`# <bin_sh_hex>` 行起 9 行一块（grep -A 8 `--` 分块），
//!   取到 jmp；无 call；jmp 目标处反汇编 100 字节到首个 `call <execve..>`。
//! - find：每个候选的每个后缀（i 从 size-2 downto 0）独立模拟 + resolve。
//!
//! 性能：全量扫描只用指令**元数据**（call/jmp 目标、rip 目标）做等价判定，
//! objdump 行文本仅在候选窗口内按需渲染（几百行），模拟器消费的 `text`
//! 每候选渲染一次复用。等价性说明：
//! - 终结 call 正则 `call.*<(exec[^+]*|posix_spawn[^+]*)>$` ⟺ 直接/rip 间接
//!   call 的注释符号以 exec/posix_spawn 开头且不含 `+`（渲染行必以 `>` 结尾）
//! - jmp_case 针 `# <hex>` ⟺ `rip_target == bin_sh`（更长的同前缀 hex 目标
//!   会超出 libc vaddr 空间，不存在）

use crate::disasm::Insn;
use crate::emulator::Emulator;
use crate::elf::Libc;
use crate::gadget::Gadget;
use crate::resolver::{self, Resolution};

/// 分支助记符表（`X86#branch?`：**整行**子串匹配）。
const BRANCH_TOKENS: [&str; 7] = ["jmp", "je", "jne", "jl", "jb", "ja", "jg"];

/// 一行（完整 objdump 行）是否分支（子串匹配，对齐 1.10.0 `branch?`）。
fn branch_line(line: &str) -> bool {
    BRANCH_TOKENS.iter().any(|t| line.contains(t))
}

/// call 注释符号是否满足 `<(exec[^+]*|posix_spawn[^+]*)>$`。
fn sym_is_terminal(s: &str) -> bool {
    !s.is_empty() && !s.contains('+') && (s.starts_with("exec") || s.starts_with("posix_spawn"))
}

/// 指令是否终结 call（元数据判定，见模块注释的等价性说明）。
fn is_terminal_call(insn: &Insn, libc: &Libc) -> bool {
    if insn.mnemonic != iced_x86::Mnemonic::Call {
        return false;
    }
    // 直接 call：注释符号 = nearest_symbol(target)
    if let Some(t) = insn.call_target {
        return sym_is_terminal(&libc.nearest_symbol(t));
    }
    // rip 间接 call：注释符号挂在 `# <target> <sym>` 尾注上
    if let Some(t) = insn.rip_target {
        return sym_is_terminal(&libc.nearest_symbol(t));
    }
    false
}

/// 构建候选窗口集合（basic-block + jmp_case）。
///
/// amd64：basic-block + jmp_case；i386：仅 basic-block（1.10.0 无 jmp_case）。
pub fn collect_candidates(libc: &Libc, insns: &[Insn]) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    out.extend(basic_block_candidates(libc, insns));
    if libc.is_x86_64() {
        out.extend(jmp_case_candidates(libc, insns));
    }
    out
}

/// basic block 候选：grep -B30 分块 → 块内首个匹配 call 切块 → slice_prefix
/// → amd64 过滤（整块 join 后 include?）。
fn basic_block_candidates(libc: &Libc, insns: &[Insn]) -> Vec<Vec<usize>> {
    let call_idxs: Vec<usize> = insns
        .iter()
        .enumerate()
        .filter(|(_, i)| is_terminal_call(i, libc))
        .map(|(i, _)| i)
        .collect();

    // grep -B 30 的 `--` 分块：块下界 = 上一匹配行 +1；首块 = ci-30（饱和）
    let mut cands: Vec<Vec<usize>> = Vec::new();
    let mut prev_match: Option<usize> = None;
    for &ci in &call_idxs {
        let lower = match prev_match {
            Some(p) => p + 1,
            None => ci.saturating_sub(30),
        };
        let start = ci.saturating_sub(30).max(lower);
        let lines: Vec<usize> = (start..=ci).collect();
        prev_match = Some(ci);

        // 窗口行文本只渲染一次，loop-shift 的多个子块复用
        let texts: Vec<String> = lines.iter().map(|&i| insns[i].render_line(libc)).collect();

        // 块内按「首个匹配行」切分（loop shift）
        let mut rest: Vec<usize> = (0..lines.len()).collect();
        loop {
            let Some(pos) = rest.iter().position(|&r| is_terminal_call(&insns[lines[r]], libc))
            else {
                break;
            };
            let block_pos: Vec<usize> = rest.drain(..=pos).collect();
            let block: Vec<usize> = block_pos.iter().map(|&r| lines[r]).collect();
            let block_texts: Vec<&str> =
                block_pos.iter().map(|&r| texts[r].as_str()).collect();
            // slice_prefix：裁掉头部到最后分支行（不含末行）
            let trimmed = slice_prefix(&block, &block_texts);
            let trimmed_texts: Vec<String> =
                trimmed.iter().map(|&i| insns[i].render_line(libc)).collect();
            // 过滤（candidates 的 select!，基于整块文本）：
            // - amd64：含 `posix_spawn@` 直通；否则含 bin_sh_hex 且末行含 `execve`
            // - i386：块文本须含 rel_sh hex（GOT 与 /bin/sh 的距离）
            let cand_text = trimmed_texts.join("\n");
            match libc.arch {
                crate::elf::Arch::X64 => {
                    if cand_text.contains("posix_spawn@") {
                        cands.push(trimmed);
                        continue;
                    }
                    let Some(bin_sh) = libc.bin_sh_offset else { continue };
                    let bin_sh_hex = format!("{bin_sh:x}");
                    if cand_text.contains(&bin_sh_hex)
                        && trimmed_texts.last().is_some_and(|l| l.contains("execve"))
                    {
                        cands.push(trimmed);
                    }
                }
                _ => {
                    if let Some(rel_sh) = libc.rel_sh() {
                        let rel_sh_hex = format!("{rel_sh:x}");
                        if cand_text.contains(&rel_sh_hex) {
                            cands.push(trimmed);
                        }
                    }
                }
            }
        }
    }
    cands
}

/// 裁掉窗口头部到最后分支行（含）——对齐 `slice_prefix`（rindex 语义）。
fn slice_prefix(lines: &[usize], texts: &[&str]) -> Vec<usize> {
    let to_rm = texts[..texts.len() - 1]
        .iter()
        .rposition(|t| branch_line(t));
    match to_rm {
        Some(r) => lines[r + 1..].to_vec(),
        None => lines.to_vec(),
    }
}

/// jmp_case：`# <bin_sh_hex>` 行起 9 行一块，到 jmp；jmp 目标反汇编到首个 call execve。
fn jmp_case_candidates(libc: &Libc, insns: &[Insn]) -> Vec<Vec<usize>> {
    let Some(bin_sh) = libc.bin_sh_offset else { return Vec::new() };
    // `grep -E '# <hex>' -A 8` ⟺ rip 相对目标恰为 bin_sh（见模块注释）
    let match_idxs: Vec<usize> = insns
        .iter()
        .enumerate()
        .filter(|(_, i)| i.rip_target == Some(bin_sh))
        .map(|(i, _)| i)
        .collect();

    let mut out = Vec::new();
    // grep -A 8 的 `--` 分块：相邻匹配（含各自 -A 尾巴）重叠时合并为一个块。
    // 块 = [首匹配, max(各匹配+8)]；对每块：块内**第一个**含 'jmp' 的行截断，
    // 截断前含 'call' → 整块丢弃（对齐 Ruby split('--') 后逐块处理）。
    let mut blocks: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<usize> = Vec::new();
    let mut cur_end: isize = -1;
    for &mi in &match_idxs {
        if !cur.is_empty() && (mi as isize) > cur_end {
            blocks.push(std::mem::take(&mut cur));
            cur_end = -1;
        }
        cur.push(mi);
        cur_end = cur_end.max((mi + 8) as isize);
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    for block in blocks {
        let first = block[0];
        let last = block.last().unwrap();
        let end = (*last + 8).min(insns.len() - 1);
        let win: Vec<usize> = (first..=end).collect();
        process_jmp_case_block(&win, insns, libc, &mut out);
    }
    out
}

/// 一个 grep -A 8 合并块的 jmp_case 处理：首 jmp 截断；截断前含 call 整块弃。
fn process_jmp_case_block(
    win: &[usize],
    insns: &[Insn],
    libc: &Libc,
    out: &mut Vec<Vec<usize>>,
) {
    // 窗口行文本（≤9+ 行），jmp/call 判定是整行子串匹配
    let texts: Vec<String> = win.iter().map(|&i| insns[i].render_line(libc)).collect();
    let Some(jmp_at) = texts.iter().position(|t| t.contains("jmp")) else {
        return;
    };
    // cand 内不允许有 call（否则该块的这条 jmp_case 被丢弃）
    if texts[..=jmp_at].iter().any(|t| t.contains("call")) {
        return;
    }
    let Some(target) = insns[win[jmp_at]].branch_target else { return };
    // 目标处开始反汇编 100 字节，到首个行含 `execve` 的 call（Ruby 语义：
    // 行子串匹配——直接 call 的 `<sym>` 或 rip 间接的 `# <hex> <sym>` 都算）
    let start_idx = match insns.binary_search_by_key(&target, |i| i.addr) {
        Ok(i) => i,
        Err(_) => return,
    };
    let mut t_idx = None;
    for i in start_idx..insns.len() {
        if insns[i].addr > target + 100 {
            return;
        }
        if insns[i].mnemonic == iced_x86::Mnemonic::Call
            && insns[i].render_line(libc).contains("execve")
        {
            t_idx = Some(i);
            break;
        }
    }
    let Some(t_idx) = t_idx else { return };
    let mut full: Vec<usize> = win[..=jmp_at].to_vec();
    full.extend(start_idx..=t_idx);
    out.push(full);
}

/// find：对每个候选的每个后缀模拟 + resolve → Gadget 列表。
pub fn find(libc: &Libc, insns: &[Insn]) -> Vec<Gadget> {
    let mut gadgets = Vec::new();
    for cand in collect_candidates(libc, insns) {
        // 每候选渲染一次操作数文本，全部后缀复用
        let texts: Vec<String> = cand.iter().map(|&i| insns[i].render_text(libc)).collect();
        // 后缀 i 从 len-2 downto 0（1.10.0：(lines.size - 2).downto(0)）
        for i in (0..cand.len().saturating_sub(1)).rev() {
            let mut emu = Emulator::new(libc.arch);
            for t in &texts[i..] {
                if !emu.step(t) {
                    break;
                }
            }
            if emu.terminal_call.is_none() {
                continue;
            }
            let Some(Resolution { constraints, effect }) = resolver::resolve(&emu, libc) else {
                continue;
            };
            let offset = insns[cand[i]].addr;
            gadgets.push(Gadget::new(offset, effect, constraints));
        }
    }
    gadgets
}
