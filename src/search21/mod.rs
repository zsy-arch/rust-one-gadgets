//! 2.1.1 管线搜索：反向 CFG 走查（master fetchers/candidate_walk.rb + base.rb#search）。
//!
//! 与 1.10.0 search.rs（grep -B30）完全独立：
//! - candidates：从每个终端 call 反向 walk（predecessors = fall-through + 分支目标），
//!   条件边 fork（MAX_FORKS=4），PATH_BUDGET=80
//! - executed_windows：候选的每个后缀（末尾 call 截断）
//! - 每后缀一次模拟 + resolve21
//!
//! 架构适配（branch_kind / call 判定 / scan_calls）在 `aarch64` 等子模块。

pub mod aarch64;
pub mod arm;
pub mod riscv64;

use crate::elf::Libc;
use crate::emulator21::processor::is_terminal_call;
use crate::gadget::Gadget;
use crate::gadget21;
use crate::resolve21;
use std::collections::{HashMap, HashSet};

/// 条件分支 fork 上限。
pub const MAX_FORKS: usize = 4;
/// 单路径长度上限。
pub const PATH_BUDGET: usize = 80;
/// call-site 窗口半径（master WINDOW_BACK/WINDOW_FWD = 0x1000，4 对齐）。
pub const WINDOW_BACK: u64 = 0x1000;
pub const WINDOW_FWD: u64 = 0x1000;

/// 架构适配 trait（fetcher 侧）。
pub trait ArchSearch {
    /// 分支分类：Some(cond?) / None = 非分支。
    /// 返回 (kind, target)；kind: 0=conditional 1=unconditional 2=terminator。
    fn branch_kind(&self, line: &str) -> Option<(u8, u64)>;
    /// call 行的目标文本（含 `<name>`）；None = 非 call。
    fn call_addr(&self, line: &str) -> Option<String>;
    /// 反汇编一段范围（textgen）。
    fn disasm(&self, libc: &Libc, lo: u64, hi: u64) -> Vec<String>;
    /// scan_calls（BL 扫描等）；None = 全量反汇编。
    fn scan_calls(&self, libc: &Libc, targets: &HashSet<u64>) -> Option<Vec<u64>>;
    /// 新模拟器状态。
    fn new_state(&self) -> crate::emulator21::processor::State;
    /// 模拟一行（process 语义：refused 记 st.refused_line；终端哨兵=成功）。
    fn process(&self, st: &mut crate::emulator21::processor::State, line: &str) -> bool;
    /// 一次 find() 的开始（arm：装载 libc 字节供 literal pool 读取）。
    fn begin(&self, _libc: &Libc) {}
    /// 候选级准备（arm：note_instruction_set + GOT 基址寄存器播种）。
    /// 返回被播种的寄存器名（resolve 时前置 GOT 约束）。
    fn prepare(
        &self,
        _st: &mut crate::emulator21::processor::State,
        _ctx: &SearchCtx,
        _lines: &[String],
    ) -> Vec<String> {
        Vec::new()
    }
    /// resolve 后约束修正（arm：GOT 基址约束前置 + writable:reg 剔除）。
    fn fixup(&self, _gots: &[String], _constraints: &mut Vec<String>) {}
}

/// prepare 的搜索上下文（全行表 + 窗口起点 + 地址索引）。
pub struct SearchCtx<'a> {
    pub lines: &'a [String],
    pub window_starts: &'a HashSet<usize>,
    pub index: &'a HashMap<u64, usize>,
}

/// 分支类型。
pub const COND: u8 = 0;
pub const UNCOND: u8 = 1;
pub const TERM: u8 = 2;

/// 一次搜索的预计算缓存。
pub struct Searcher<'a> {
    libc: &'a Libc,
    arch: &'a dyn ArchSearch,
    /// 全部行。
    pub lines: Vec<String>,
    /// 行索引 → 地址。
    addr_at: Vec<u64>,
    /// 地址 → 行索引。
    index: HashMap<u64, usize>,
    /// 窗口起点（多个窗口拼接时行间无 fall-through）。
    window_starts: HashSet<usize>,
    /// 目标地址 → 分支行索引（branch_pred_map）。
    branch_pred_map: HashMap<u64, Vec<usize>>,
}

impl<'a> Searcher<'a> {
    pub fn new(libc: &'a Libc, arch: &'a dyn ArchSearch) -> Self {
        // 窗口模式：scan_calls 定位 call sites，只反汇编附近
        let targets = terminal_targets(libc);
        let (lines, window_starts) = match arch.scan_calls(libc, &targets) {
            Some(sites) if !sites.is_empty() => windowed(libc, arch, &sites),
            _ => (arch.disasm(libc, 0, u64::MAX), HashSet::new()),
        };
        let addr_at: Vec<u64> = lines
            .iter()
            .map(|l| {
                let s = l.trim_start();
                let end = s.find(':').unwrap_or(0);
                u64::from_str_radix(&s[..end], 16).unwrap_or(0)
            })
            .collect();
        let index: HashMap<u64, usize> =
            addr_at.iter().enumerate().map(|(i, &a)| (a, i)).collect();
        // branch_pred_map：一遍扫描全部分支行
        let mut branch_pred_map: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, line) in lines.iter().enumerate() {
            if let Some((kind, tgt)) = arch.branch_kind(line) {
                if kind == COND || kind == UNCOND {
                    branch_pred_map.entry(tgt).or_default().push(i);
                }
            }
        }
        Searcher { libc, arch, lines, addr_at, index, window_starts, branch_pred_map }
    }

    /// 全部 gadget（base.rb#search）。
    pub fn find(&self) -> Vec<Gadget> {
        self.arch.begin(self.libc);
        let mut gadgets = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut refused: HashSet<String> = HashSet::new();
        for cand in self.candidates() {
            for suffix in executed_windows(&cand) {
                let key = suffix.join("\n");
                if !seen.insert(key) {
                    continue;
                }
                if refused_before_call(&refused, &suffix) {
                    continue;
                }
                if let Ok(Some(g)) = self.resolve_suffix(&suffix) {
                    gadgets.push(g);
                }
                if let Some(line) = LAST_REFUSED.take() {
                    refused.insert(line);
                }
            }
        }
        gadgets
    }

    /// branch_aware_candidates：每个终端 call 反向 walk。
    fn candidates(&self) -> Vec<Vec<String>> {
        let mut cands: Vec<Vec<String>> = Vec::new();
        for (idx, line) in self.lines.iter().enumerate() {
            if self.arch.call_addr(line).is_some() && self.terminal_call_line(line) {
                let mut visited = HashSet::new();
                let mut path: Vec<usize> = Vec::new();
                self.back_walk(idx, 0, &mut visited, &mut path, &mut cands);
            }
        }
        // master：候选不排序（发现序 uniq），found 序决定 all_gadgets 平局序
        cands.dedup();
        cands
    }

    /// back_walk：DFS 反向；path 前序；emit 叶。
    fn back_walk(
        &self,
        idx: usize,
        forks: usize,
        visited: &mut HashSet<u64>,
        path: &mut Vec<usize>,
        out: &mut Vec<Vec<String>>,
    ) {
        let addr = self.addr_at[idx];
        if path.len() >= PATH_BUDGET {
            out.push(self.path_lines(path));
            return;
        }
        visited.insert(addr);
        path.insert(0, idx);
        let edges: Vec<(usize, bool)> = self
            .predecessors(idx)
            .into_iter()
            .filter(|(pidx, cond)| {
                !visited.contains(&self.addr_at[*pidx]) && !(*cond && forks >= MAX_FORKS)
            })
            .collect();
        if edges.is_empty() {
            out.push(self.path_lines(path));
        } else {
            for (pidx, cond) in edges {
                self.back_walk(pidx, forks + cond as usize, visited, path, out);
            }
        }
        path.remove(0);
        visited.remove(&addr);
    }

    fn path_lines(&self, path: &[usize]) -> Vec<String> {
        path.iter().map(|&i| self.lines[i].clone()).collect()
    }

    /// predecessors：fall-through（idx-1，非窗口头、非无条件/terminator）+ 分支目标为 addr 的行。
    fn predecessors(&self, idx: usize) -> Vec<(usize, bool)> {
        let mut preds = Vec::new();
        if idx > 0 && !self.window_starts.contains(&idx) {
            if let Some((kind, _)) = self.arch.branch_kind(&self.lines[idx - 1]) {
                if kind != UNCOND && kind != TERM {
                    preds.push((idx - 1, kind == COND));
                }
            } else {
                preds.push((idx - 1, false));
            }
        }
        // branch_pred_map：target==addr 的分支行
        if let Some(preds_map) = self.branch_pred_map.get(&self.addr_at[idx]) {
            for &b in preds_map {
                let kind = self.arch.branch_kind(&self.lines[b]).map(|(k, _)| k);
                preds.push((b, kind == Some(COND)));
            }
        }
        preds
    }

    /// terminal_call_line：call 且 <name> 匹配 TERMINAL_CALL_RE。
    fn terminal_call_line(&self, line: &str) -> bool {
        let Some(addr) = self.arch.call_addr(line) else { return false };
        if let Some(start) = addr.find('<') {
            let name = addr[start + 1..].split('@').next().unwrap_or("");
            let name = name.strip_suffix('>').unwrap_or(name);
            return is_terminal_call(name);
        }
        false
    }
}

thread_local! {
    static LAST_REFUSED: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// executed_windows（master Base#executed_windows）：每个后缀（最长优先产出顺序
/// 按 i 从 size-2 downto 0），遇终端 call 截断到该 call（含）。
pub fn executed_windows(lines: &[String]) -> Vec<Vec<String>> {
    // terminal call 行判定闭包（分支/调用判定走 arch 不可得；按 <name> 文本判定）
    let is_term = |l: &str| -> bool {
        let Some(pos) = l.find('<') else { return false };
        if !l.contains("bl") && !l.contains("jal") && !l.contains("call") && !l.contains("jalr") {
            return false;
        }
        let name = l[pos + 1..].split('@').next().unwrap_or("");
        let name = name.strip_suffix('>').unwrap_or(name);
        is_terminal_call(name)
    };
    let mut wins = Vec::new();
    let mut stop: Option<usize> = None;
    for i in (0..lines.len().saturating_sub(1)).rev() {
        if is_term(&lines[i]) {
            stop = Some(i);
        }
        let end = stop.unwrap_or(lines.len());
        wins.push(lines[i..=end.min(lines.len() - 1)].to_vec());
    }
    wins
}

/// refused_before_call。
fn refused_before_call(refused: &HashSet<String>, window: &[String]) -> bool {
    if refused.is_empty() {
        return false;
    }
    window[..window.len().saturating_sub(1)]
        .iter()
        .any(|l| refused.contains(l))
}

impl<'a> Searcher<'a> {
/// resolve_suffix：模拟 + resolve21（失败返回 Ok(None)；refused 行经 thread_local 带出）。
fn resolve_suffix(&self, lines: &[String]) -> Result<Option<Gadget>, ()> {
    let (libc, arch) = (self.libc, self.arch);
    let ctx = SearchCtx { lines: &self.lines, window_starts: &self.window_starts, index: &self.index };
    let mut st = arch.new_state();
    let gots = arch.prepare(&mut st, &ctx, lines);
    let mut reached_call = false;
    for l in lines {
        if !arch.process(&mut st, l) {
            if let Some(r) = st.refused_line.clone() {
                LAST_REFUSED.replace(Some(r));
            }
            return Ok(None);
        }
        // 终端 call 行（哨兵）：窗口到此为止，resolve 接管
        if st.refused_line.is_none() && matches!(st.registers.get(&st.pc.clone()), crate::emulator21::Val::Str(_)) {
            reached_call = true;
            break;
        }
    }
    if !reached_call {
        return Ok(None);
    }
    let Ok((constraints, effect)) = resolve21::resolve(&mut st, libc) else {
        return Ok(None);
    };
    // master resolve_suffix 尾部：矛盾丢弃、恒真剔除
    let Some(constraints) = resolve21::finalize(constraints) else {
        return Ok(None);
    };
    let offset = lines
        .first()
        .map(|l| {
            let s = l.trim_start();
            let end = s.find(':').unwrap_or(0);
            u64::from_str_radix(&s[..end], 16).unwrap_or(0)
        })
        .unwrap_or(0);
    // master：prune_settled 在 Gadget 构造器内执行；arm 的 GOT 约束前置
    let mut constraints = gadget21::prune_settled(constraints);
    arch.fixup(&gots, &mut constraints);
    Ok(Some(Gadget::new(offset, effect, constraints)))
}
}

/// 终端符号地址集（.dynsym/.symtab 前缀 exec/posix_spawn）。
fn terminal_targets(libc: &Libc) -> HashSet<u64> {
    libc.symbol_names
        .iter()
        .filter(|(_, name)| {
            let n = name.split('@').next().unwrap_or(name);
            n.starts_with("exec") || n.starts_with("posix_spawn")
        })
        .map(|(&a, _)| a)
        .collect()
}

/// 窗口化反汇编（merge_ranges + textgen）。
fn windowed(
    libc: &Libc,
    arch: &dyn ArchSearch,
    sites: &[u64],
) -> (Vec<String>, HashSet<usize>) {
    let mut sorted: Vec<u64> = sites.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for &a in &sorted {
        let lo = a.saturating_sub(WINDOW_BACK);
        let hi = a + WINDOW_FWD;
        match merged.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    let mut lines = Vec::new();
    let mut starts = HashSet::new();
    for (lo, hi) in merged {
        starts.insert(lines.len());
        lines.extend(arch.disasm(libc, lo, hi));
    }
    (lines, starts)
}


#[cfg(test)]
mod tests {
    use super::*;

    /// 2.27 样本管线阶段数：golden 断言在 tests/golden_arch.rs，这里只保住
    /// 「能跑完且 found 集非空 + 关键 offset 在集内」的回归下限。
    #[test]
    fn searcher_finds_key_offsets_227() {
        let dir = std::env::var_os("ROG_LIBC_SAMPLES_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(
                "ROG_LIBC_SAMPLES_DIR",
            ));
        let p = dir.join("glibc/aarch64/libc-2.27.so");
        let Ok(data) = std::fs::read(&p) else {
            return;
        };
        let libc = crate::elf::Libc::parse(data).unwrap();
        let arch = crate::search21::aarch64::Aarch64Search;
        let s = Searcher::new(&libc, &arch);
        let gadgets = s.find();
        assert!(!gadgets.is_empty(), "2.27 found set must be non-empty");
        assert!(gadgets.iter().any(|g| g.offset == 0x3f160), "0x3f160 must be found");
        assert!(gadgets.iter().any(|g| g.offset == 0xa32e8), "0xa32e8 must be found");

        // 2.24：0x9cec8（maybe_script_execute → execvpe 内 execve）
        let p224 = dir.join("glibc/aarch64/libc-2.24.so");
        if let Ok(data) = std::fs::read(&p224) {
            let libc = crate::elf::Libc::parse(data).unwrap();
            let s = Searcher::new(&libc, &arch);
            let g224 = s.find();
            assert!(g224.iter().any(|g| g.offset == 0x9cec8), "0x9cec8 must be found");
        }
    }
}
