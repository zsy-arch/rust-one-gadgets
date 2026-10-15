//! mips 的 ArchSearch 实现（master fetchers/mips.rb）。
//!
//! 与其他架构的差异（master mips.rb 顶部声明）：
//! - 调用不写目标：`lw t9,-off(gp)` 从 GOT 装入 → rewrite（name_got_calls）
//!   把符号名写到 jalr 行尾；GOT 全局槽值以 `  # <addr>` 尾注写入
//!   （state_got_values），模拟器 load_value 读成 `$base+<addr>`
//! - 延迟槽：转移下一指令先执行 → delay_edges（分支边从延迟槽出发）、
//!   emulate_lines（窗口补上 call 的延迟槽行）、filter_windows 三过滤
//! - GOT 基址在 gp：resolve 覆写——got 约束前置（got_preconditions：
//!   窗口内 gp 被改写时加 `[holder] is the GOT address of libc`）+
//!   gp 根 writable/readable 约束剔除

use super::{ArchSearch, SearchCtx, COND, TERM, UNCOND};
use crate::elf::Libc;
use crate::emulator21::processor::{mnemonic_of, EmuError, State};
use std::collections::{HashMap, HashSet};

pub struct MipsSearch;

/// read_mips_got（master）：DT_PLTGOT 地址 → 文件偏移；DT_MIPS_LOCAL_GOTNO /
/// DT_MIPS_GOTSYM；dynsym (value,name) 全表（gotsym 起的全局槽一一对应）。
struct RawGot {
    offset: u64,
    local: u64,
    gotsym: u64,
    symbols: Vec<(u64, Option<String>)>,
    /// value → name（非零 value 非空名；本地槽名查找）。
    names: HashMap<u64, String>,
    big: bool,
}

/// 惰性构建的搜索上下文：GOT 表 + 代码字表（loaded_code）。
struct MipsCtx {
    got: Option<RawGot>,
    /// 可执行段基址 + 4 字节字表（derives_got_base? 的 prologue 扫描）。
    code_base: u64,
    code_words: Vec<u32>,
}

thread_local! {
    static MIPS_CTX: std::cell::RefCell<Option<(String, MipsCtx)>> =
        const { std::cell::RefCell::new(None) };
}

/// ensure_ctx：按 build_id（无则 data 指纹）缓存构建。
fn ensure_ctx(libc: &Libc) {
    let key = libc
        .build_id
        .clone()
        .unwrap_or_else(|| format!("{:p}/{}", libc.data.as_ptr(), libc.data.len()));
    MIPS_CTX.with(|c| {
        let mut c = c.borrow_mut();
        if c.as_ref().is_some_and(|(k, _)| *k == key) {
            return;
        }
        *c = Some((key, build_ctx(libc)));
    });
}

fn build_ctx(libc: &Libc) -> MipsCtx {
    let got = build_raw_got(libc);
    let (code_base, code_words) = match libc.executable_segment() {
        Some(seg) => {
            let data = &libc.data[seg.file_off as usize..(seg.file_off + seg.file_size) as usize];
            let el = libc.mips_el;
            let words: Vec<u32> = data
                .chunks_exact(4)
                .map(|c| {
                    if el {
                        u32::from_le_bytes([c[0], c[1], c[2], c[3]])
                    } else {
                        u32::from_be_bytes([c[0], c[1], c[2], c[3]])
                    }
                })
                .collect();
            (seg.vaddr, words)
        }
        None => (0, Vec::new()),
    };
    MipsCtx { got, code_base, code_words }
}

const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
const DT_MIPS_GOTSYM: u64 = 0x7000_0013;

fn build_raw_got(libc: &Libc) -> Option<RawGot> {
    let obj = goblin::elf::Elf::parse(&libc.data).ok()?;
    let mut local = None;
    let mut gotsym = None;
    if let Some(d) = obj.dynamic.as_ref() {
        for e in &d.dyns {
            if e.d_tag == DT_MIPS_LOCAL_GOTNO {
                local = Some(e.d_val);
            } else if e.d_tag == DT_MIPS_GOTSYM {
                gotsym = Some(e.d_val);
            }
        }
    }
    let pltgot = libc.pltgot?;
    let (local, gotsym) = (local?, gotsym?);
    let offset = libc.vaddr_to_off(pltgot)?;
    let mut symbols = Vec::new();
    for s in obj.dynsyms.iter() {
        let name = obj.dynstrtab.get_at(s.st_name).map(|n| n.to_string());
        symbols.push((s.st_value, name));
    }
    let mut names = HashMap::new();
    for (v, n) in &symbols {
        if *v != 0 && n.as_deref().is_some_and(|n| !n.is_empty()) {
            names.entry(*v).or_insert_with(|| n.clone().unwrap());
        }
    }
    Some(RawGot { offset, local, gotsym, symbols, names, big: !libc.mips_el })
}

impl MipsSearch {
    /// got_entry（master）：(槽内地址, 符号名)；GP_BIAS=0x7ff0。
    /// 本地槽（index < local）读文件字，名按地址查 names（可为 None）；
    /// 全局槽 = symbols[gotsym + index - local]。
    fn got_entry(gp_offset: i64) -> Option<(u64, Option<String>)> {
        MIPS_CTX.with(|c| {
            let ctx = c.borrow();
            let ctx = ctx.as_ref()?.1.got.as_ref()?;
            let index = 0x7ff0i64 + gp_offset;
            if index < 0 || index % 4 != 0 {
                return None;
            }
            let index = (index / 4) as u64;
            if index < ctx.local {
                let pos = ctx.offset as usize + (index as usize) * 4;
                if pos + 4 > libc_len() {
                    return None;
                }
                let bytes = libc_bytes(pos, pos + 4)?;
                let b = if ctx.big {
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } as u64;
                let name = ctx.names.get(&b).cloned();
                Some((b, name))
            } else {
                let sym_idx = ctx.gotsym + index - ctx.local;
                let (v, n) = ctx.symbols.get(sym_idx as usize)?;
                Some((*v, n.clone()))
            }
        })
    }

    fn got_address(gp_offset: i64) -> Option<u64> {
        Self::got_entry(gp_offset).map(|(a, _)| a)
    }

    fn got_symbol(gp_offset: i64) -> Option<String> {
        Self::got_entry(gp_offset).and_then(|(_, n)| n)
    }

    /// master mips.rb#environ?：names[offset] 匹配 /\A_*environ\z/
    /// （offset 来自 `$base+0xN` 的 GOT 槽内容；非 mips 搜索时 ctx 为空 → false）。
    pub fn environ_at(offset: u64) -> bool {
        MIPS_CTX.with(|c| {
            let ctx = c.borrow();
            ctx.as_ref()
                .and_then(|(_, cx)| cx.got.as_ref())
                .and_then(|g| g.names.get(&offset))
                .is_some_and(|n| n.trim_start_matches('_') == "environ")
        })
    }

    /// derives_got_base?：函数前 PROLOGUE_WORDS=4 条内出现
    /// `addu gp,gp,t9`（0x0399e021）——o32 被调方从 t9 推自身 GOT 基址。
    fn derives_got_base(address: u64) -> bool {
        MIPS_CTX.with(|c| {
            let ctx = c.borrow();
            let Some(ctx) = ctx.as_ref() else { return false };
            let index = (address as i64 - ctx.1.code_base as i64) / 4;
            if index < 0 {
                return false;
            }
            let start = index as usize;
            (0..4).any(|i| ctx.1.code_words.get(start + i) == Some(&0x0399_e021))
        })
    }
}

thread_local! {
    /// ensure_ctx 时装载的 libc 字节（GOT 本地槽读取）。
    static LIBC_BYTES: std::cell::RefCell<Option<(String, std::rc::Rc<Vec<u8>>)>> =
        const { std::cell::RefCell::new(None) };
}

fn load_libc_bytes(libc: &Libc) {
    let key = libc
        .build_id
        .clone()
        .unwrap_or_else(|| format!("{:p}/{}", libc.data.as_ptr(), libc.data.len()));
    LIBC_BYTES.with(|c| {
        let mut c = c.borrow_mut();
        if c.as_ref().is_some_and(|(k, _)| *k == key) {
            return;
        }
        *c = Some((key, std::rc::Rc::new(libc.data.clone())));
    });
}

fn libc_len() -> usize {
    LIBC_BYTES.with(|c| c.borrow().as_ref().map_or(0, |(_, d)| d.len()))
}

fn libc_bytes(lo: usize, hi: usize) -> Option<std::rc::Rc<[u8]>> {
    // 局部小读取：直接切片拷贝（Rc<Vec> 无法借出生命周期）
    LIBC_BYTES.with(|c| {
        let c = c.borrow();
        let d = c.as_ref()?.1.clone();
        drop(c);
        let slice = d.get(lo..hi)?.to_vec();
        Some(slice.into())
    })
}

// ---- 行级正则等价物（master mips.rb 私有常量） ----

/// 行体（剥地址前缀）。
fn body_of(line: &str) -> &str {
    let s = line.trim_start();
    match s.find(':') {
        Some(c) if !s[..c].is_empty() && s[..c].chars().all(|x| x.is_ascii_hexdigit()) => {
            s[c + 1..].trim_start()
        }
        _ => s,
    }
}

/// GOT_LOAD = /:\s*lw\s+t9,(-?\d+)\(gp\)/。
fn got_load(line: &str) -> Option<i64> {
    let rest = body_of(line).strip_prefix("lw")?.trim_start();
    let rest = rest.strip_prefix("t9,")?;
    rest.strip_suffix("(gp)")?.parse().ok()
}

/// GOT_GLOBAL_LOAD = /:\s*lw\s+(?!t9,)\w+,(-?\d+)\(gp\)/。
fn got_global_load(line: &str) -> Option<i64> {
    let rest = body_of(line).strip_prefix("lw")?.trim_start();
    let reg_end = rest.find(',')?;
    let reg = &rest[..reg_end];
    if reg.is_empty() || !reg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    if reg == "t9" {
        return None; // (?!t9,) 负向断言
    }
    let off = rest[reg_end + 1..].strip_suffix("(gp)")?;
    off.parse().ok()
}

/// INDIRECT_CALL = /:\s*jalr\s+(?:\w+,)?t9\s*\z/。
fn is_indirect_call(line: &str) -> bool {
    let Some(rest) = body_of(line).strip_prefix("jalr") else { return false };
    let rest = rest.trim_start();
    match rest.strip_suffix("t9") {
        Some(mid) => mid.is_empty() || mid.ends_with(','),
        None => false,
    }
}

/// TARGET_WRITE = /:\s*(?!s[whb]\b)\S+\s+t9,/（t9 的其他写；s[whb] store 读不算）。
fn is_target_write(line: &str) -> bool {
    let body = body_of(line);
    let Some((mnem, rest)) = body.split_once(char::is_whitespace) else { return false };
    let mb = mnem.as_bytes();
    if mb.len() >= 2
        && mb[0] == b's'
        && matches!(mb[1], b'w' | b'h' | b'b')
        && mnem[2..].chars().next().is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
    {
        return false;
    }
    rest.trim_start().starts_with("t9,")
}

/// DIRECT_CALL = /:\s*(?:bal|jal)\s+([0-9a-f]+)/。
fn direct_call_target(line: &str) -> Option<u64> {
    let body = body_of(line);
    let rest = body
        .strip_prefix("bal")
        .or_else(|| body.strip_prefix("jal"))?
        .trim_start();
    if body.starts_with("jalr") {
        return None;
    }
    let tok: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (!tok.is_empty()).then(|| u64::from_str_radix(&tok, 16).ok())?
}

/// 行首地址。
fn line_addr(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let end = s.find(':')?;
    (!s[..end].is_empty() && s[..end].chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(&s[..end], 16).ok())?
}

/// 行内分支目标（master branch_target：后跟 `<` 或行尾的 hex 词）。
fn target_of(line: &str) -> Option<u64> {
    let rest = body_of(line);
    let rest = rest.split_once(char::is_whitespace).map(|(_, r)| r).unwrap_or("");
    let rest = rest.split('#').next().unwrap_or(rest);
    let mut best: Option<&str> = None;
    for tok in rest.split(|c: char| c == ',' || c.is_whitespace()) {
        if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_hexdigit()) {
            best = Some(tok);
        }
    }
    best.and_then(|t| u64::from_str_radix(t, 16).ok())
}

// ---- 三过滤（executed_windows 覆写） ----

/// follows_a_transfer_it_skipped?：window[1] 地址 != window[0]+4。
fn follows_a_transfer_it_skipped(w: &[String]) -> bool {
    if w.len() < 2 {
        return false;
    }
    match (line_addr(&w[0]), line_addr(&w[1])) {
        (Some(a), Some(b)) => b != a + 4,
        _ => false,
    }
}

/// enters_at_an_unset_call?：首行 jalr。
fn enters_at_an_unset_call(w: &[String]) -> bool {
    w.first().is_some_and(|l| mnemonic_of(l) == "jalr")
}

/// calls_without_the_callee_in_t9?：直接调用目标要求 t9 已装载
/// （目标函数从 t9 推 gp；held != target 且 derives_got_base → 过滤）。
fn calls_without_the_callee_in_t9(w: &[String]) -> bool {
    let mut held: Option<u64> = None;
    for line in w {
        if let Some(off) = got_load(line) {
            held = MipsSearch::got_address(off);
        } else if let Some(target) = direct_call_target(line) {
            if held != Some(target) && MipsSearch::derives_got_base(target) {
                return true;
            }
        } else if is_target_write(line) {
            held = None;
        }
    }
    false
}

// ---- GOT 行改写（objdump_lines 覆写） ----

/// name_got_calls：jalr t9 行尾附 ` <name>`（最近一次 lw t9,-off(gp) 的槽）。
fn name_got_calls(lines: Vec<String>) -> Vec<String> {
    let mut loaded: Option<i64> = None;
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        if let Some(off) = got_load(&line) {
            loaded = Some(off);
            out.push(line);
        } else if is_indirect_call(&line) {
            let name = loaded.and_then(MipsSearch::got_symbol);
            loaded = None;
            out.push(match name {
                Some(n) => format!("{line} <{n}>"),
                None => line,
            });
        } else {
            if is_target_write(&line) {
                loaded = None;
            }
            out.push(line);
        }
    }
    out
}

/// state_got_values：非 t9 的 GOT 装载行尾注 `  # <addr>`。
fn state_got_values(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| match got_global_load(&line) {
            Some(off) => match MipsSearch::got_address(off) {
                Some(a) if a != 0 => format!("{line}  # {a:x}"),
                _ => line,
            },
            None => line,
        })
        .collect()
}

impl ArchSearch for MipsSearch {
    /// branch_kind：COND.key? → conditional；b → unconditional；jr/j → terminator。
    fn branch_kind(&self, line: &str) -> Option<(u8, u64)> {
        let m = mnemonic_of(line);
        if matches!(
            m,
            "beq" | "bne" | "beqz" | "bnez" | "blez" | "bgtz" | "bltz" | "bgez"
        ) {
            return Some((COND, target_of(line)?));
        }
        if m == "b" {
            return Some((UNCOND, target_of(line)?));
        }
        if m == "jr" || m == "j" {
            return Some((TERM, 0));
        }
        None
    }

    /// call_str = (?:jalr|jal|bal)。jalr 目标 = 最后操作数（名由 rewrite 写入）；
    /// jal/bal = 首 token + `<name>` 尾注。
    fn call_addr(&self, line: &str) -> Option<String> {
        let m = mnemonic_of(line);
        if !matches!(m, "jalr" | "jal" | "bal") {
            return None;
        }
        let rest = body_of(line).split_once(char::is_whitespace)?.1;
        let rest = rest.split('#').next().unwrap_or(rest).trim();
        if m == "jalr" {
            return rest.split_whitespace().last().map(|s| s.to_string());
        }
        let mut out = String::new();
        for (i, tok) in rest.split_whitespace().enumerate() {
            if i == 0 {
                out.push_str(tok);
            } else if tok.starts_with('<') {
                out.push(' ');
                out.push_str(tok);
            }
        }
        Some(out)
    }

    /// 全量路径：逐 AX section（objdump -d 语义）；窗口路径：单区间。
    fn disasm(&self, libc: &Libc, lo: u64, hi: u64) -> Vec<String> {
        if hi == u64::MAX {
            let mut out = Vec::new();
            for &(saddr, ssize) in &libc.mips_code_sections {
                out.extend(crate::textgen::mips::disassemble_range(libc, saddr, saddr + ssize));
            }
            return out;
        }
        crate::textgen::mips::disassemble_range(libc, lo, hi)
    }

    /// scan_calls：CALL_OPCODES={0x23,0x01,0x03} 逐字扫；
    /// call_destination（lw t9 → got_address；bal → pc 相对；jal → 区域内绝对）。
    fn scan_calls(&self, libc: &Libc, targets: &HashSet<u64>) -> Option<Vec<u64>> {
        ensure_ctx(libc);
        load_libc_bytes(libc);
        let seg = libc.executable_segment()?;
        let base = seg.vaddr;
        let data = &libc.data[seg.file_off as usize..(seg.file_off + seg.file_size) as usize];
        let be = !libc.mips_el;
        let mut sites = Vec::new();
        for (i, chunk) in data.chunks_exact(4).enumerate() {
            let word = if be {
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            } else {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            };
            let op = word >> 26;
            if op != 0x23 && op != 0x01 && op != 0x03 {
                continue;
            }
            let address = base + (i as u64) * 4;
            if let Some(d) = call_destination(word, address) {
                if targets.contains(&d) {
                    sites.push(address);
                }
            }
        }
        Some(sites)
    }

    fn new_state(&self) -> State {
        crate::emulator21::mips::new_state()
    }

    fn begin(&self, libc: &Libc) {
        ensure_ctx(libc);
        load_libc_bytes(libc);
    }

    fn process(&self, st: &mut State, line: &str) -> bool {
        match crate::emulator21::mips::process_line(st, line) {
            Ok(()) => true,
            Err(EmuError::UnsupportedInstruction(m)) => {
                st.refused_line = Some(m);
                false
            }
            Err(EmuError::UnsupportedInstructionArgument(m)) if m == "__terminal__" => true,
            Err(_) => false,
        }
    }

    /// objdump_lines 覆写：state_got_values(name_got_calls(lines))。
    fn rewrite(&self, libc: &Libc, lines: Vec<String>) -> Vec<String> {
        ensure_ctx(libc);
        load_libc_bytes(libc);
        state_got_values(name_got_calls(lines))
    }

    /// branch_pred_map 覆写：每条边 +1（延迟槽），窗口首行处丢弃。
    fn delay_edges(
        &self,
        map: HashMap<u64, Vec<usize>>,
        starts: &HashSet<usize>,
    ) -> HashMap<u64, Vec<usize>> {
        map.into_iter()
            .map(|(target, idxs)| {
                (
                    target,
                    idxs.into_iter().filter_map(|i| (!starts.contains(&(i + 1))).then_some(i + 1)).collect(),
                )
            })
            .collect()
    }

    /// executed_windows 覆写：三过滤。
    fn filter_windows(&self, libc: &Libc, wins: Vec<Vec<String>>) -> Vec<Vec<String>> {
        ensure_ctx(libc);
        load_libc_bytes(libc);
        wins.into_iter()
            .filter(|w| {
                !follows_a_transfer_it_skipped(w)
                    && !enters_at_an_unset_call(w)
                    && !calls_without_the_callee_in_t9(w)
            })
            .collect()
    }

    /// emulate 覆写：窗口末尾是终端 call 时补延迟槽行。
    fn emulate_lines(&self, ctx: &SearchCtx, lines: &[String]) -> Vec<String> {
        let Some(last) = lines.last() else { return lines.to_vec() };
        if !terminal_call_line(last) {
            return lines.to_vec();
        }
        let Some(addr) = line_addr(last) else {
            return lines.to_vec();
        };
        let Some(&idx) = ctx.index.get(&addr) else {
            return lines.to_vec();
        };
        let next = idx + 1;
        if ctx.window_starts.contains(&next) {
            return lines.to_vec();
        }
        let Some(delay) = ctx.lines.get(next) else {
            return lines.to_vec();
        };
        let mut out = lines.to_vec();
        out.push(delay.clone());
        out
    }

    /// resolve 覆写（got_base_constraint + got_preconditions + gp 根剔除）。
    fn fixup(&self, st: &State, _gots: &[String], constraints: &mut Vec<String>) {
        let got = "gp is the GOT address of libc".to_string();
        // got_preconditions：gp 被窗口改写 → 追加改写值的约束
        let held = st.registers.get("gp").to_string();
        let mut pre = vec![got];
        if held != "gp" {
            pre.push(format!("{held} is the GOT address of libc"));
        }
        // reject! /\A(?:writable|readable): \[*gp\b/
        constraints.retain(|c| !gp_rooted(c));
        for p in pre.into_iter().rev() {
            constraints.insert(0, p);
        }
    }
}

/// `writable: [*[gp\b` 前缀约束（resolve 覆写的 reject!）。
fn gp_rooted(c: &str) -> bool {
    let Some(rest) = c.strip_prefix("writable: ").or_else(|| c.strip_prefix("readable: ")) else {
        return false;
    };
    let rest = rest.trim_start_matches('[');
    let Some(after) = rest.strip_prefix("gp") else { return false };
    after.is_empty() || !after.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// terminal_call_line?（call + 严格终端名）。
fn terminal_call_line(line: &str) -> bool {
    let m = mnemonic_of(line);
    if !matches!(m, "jalr" | "jal" | "bal") {
        return false;
    }
    let Some(rest) = body_of(line).split_once(char::is_whitespace).map(|(_, r)| r) else {
        return false;
    };
    let Some(pos) = rest.find('<') else { return false };
    let name = rest[pos + 1..].split('@').next().unwrap_or("");
    let name = name.strip_suffix('>').unwrap_or(name);
    crate::emulator21::processor::is_terminal_call(name)
}

/// call_destination（master）：
/// - 0x8f990000（lw t9,imm(gp)）→ got_address(imm)
/// - 0x04110000（bal）→ (addr+4) + imm*4
/// - opcode==3（jal）→ ((addr+4) & 0xf0000000) | target<<2
fn call_destination(word: u32, address: u64) -> Option<u64> {
    let following = address + 4;
    match word & 0xffff_0000 {
        0x8f99_0000 => {
            let half = (word & 0xffff) as i64;
            let imm = if half >= 0x8000 { half - 0x1_0000 } else { half };
            MipsSearch::got_address(imm)
        }
        0x0411_0000 => {
            let half = (word & 0xffff) as i64;
            let imm = if half >= 0x8000 { half - 0x1_0000 } else { half };
            Some((following as i64 + imm * 4) as u64)
        }
        _ if (word >> 26) == 3 => {
            Some((following & 0xf000_0000) | (((word & 0x03ff_ffff) as u64) << 2))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_kind() {
        let s = MipsSearch;
        assert_eq!(s.branch_kind("0:\tbne\tv1,a3,30600 <x>"), Some((COND, 0x30600)));
        assert_eq!(s.branch_kind("0:\tbeqz\tv0,85fa4 <x>"), Some((COND, 0x85fa4)));
        assert_eq!(s.branch_kind("0:\tb\t2740c <x>"), Some((UNCOND, 0x2740c)));
        assert_eq!(s.branch_kind("0:\tjr\tra"), Some((TERM, 0)));
        assert_eq!(s.branch_kind("0:\tj\t2c2 <x>"), Some((TERM, 0)));
        assert_eq!(s.branch_kind("0:\tjalr\tt9"), None);
        assert_eq!(s.branch_kind("0:\taddu\tv0,v0,v1"), None);
    }

    #[test]
    fn test_call_addr() {
        let s = MipsSearch;
        assert_eq!(
            s.call_addr("4b3e0:\tjalr\tt9 <posix_spawn>"),
            Some("<posix_spawn>".to_string())
        );
        assert_eq!(
            s.call_addr("0:\tjal\t2c2 <execve@@GLIBC_2.0>"),
            Some("2c2 <execve@@GLIBC_2.0>".to_string())
        );
        assert_eq!(s.call_addr("0:\tbal\t6653c <x>"), Some("6653c <x>".to_string()));
        assert_eq!(s.call_addr("0:\tlw\tt9,-31652(gp)"), None);
    }

    #[test]
    fn test_call_destination() {
        // bal（0x04110004 @ 4b3dc）：4b3e0 + 0x10 = 4b3f0
        assert_eq!(call_destination(0x0411_0004, 0x4b3dc), Some(0x4b3f0));
        // jal：(following & region) | target<<2
        let word = 0x0c00_1234u32;
        assert_eq!(
            call_destination(word, 0x1000),
            Some((0x1004 & 0xf000_0000) | (0x1234 << 2))
        );
        // 非 call 字
        assert_eq!(call_destination(0x2468_0000, 0x1000), None);
    }

    #[test]
    fn test_line_predicates() {
        assert!(is_indirect_call("0:\tjalr\tt9"));
        assert!(is_indirect_call("0:\tjalr\tra,t9"));
        assert!(!is_indirect_call("0:\tjalr\tt8"));
        assert!(!is_indirect_call("0:\tjal\t2c2"));
        assert!(is_target_write("0:\taddiu\tt9,t9,1"));
        assert!(is_target_write("0:\tmove\tt9,v0"));
        assert!(!is_target_write("0:\tsw\tt9,4(sp)"));
        assert!(is_target_write("0:\tlw\tt9,-31652(gp)")); // 正则命中（GOT_LOAD 先判）
        assert_eq!(got_load("0:\tlw\tt9,-31652(gp)"), Some(-31652));
        assert_eq!(got_load("0:\tlw\ta0,-32496(gp)"), None);
        assert_eq!(got_global_load("0:\tlw\ta0,-32496(gp)"), Some(-32496));
        assert_eq!(got_global_load("0:\tlw\tt9,-32496(gp)"), None);
    }

    #[test]
    fn test_gp_rooted() {
        assert!(gp_rooted("writable: gp"));
        assert!(gp_rooted("writable: [gp-0x7ff0]"));
        assert!(gp_rooted("readable: gp"));
        assert!(!gp_rooted("writable: gpa"));
        assert!(!gp_rooted("writable: sp+0x10"));
        assert!(!gp_rooted("gp is the GOT address of libc"));
    }

    #[test]
    fn test_filters() {
        let w = vec![
            "4b3dc:\tlw\tt9,-31652(gp)".to_string(),
            "4b3e0:\tjalr\tt9".to_string(),
        ];
        assert!(!follows_a_transfer_it_skipped(&w));
        assert!(enters_at_an_unset_call(&w[1..]));
        let w2 = vec![
            "1000:\tbeqz\ta0,2000 <x>".to_string(),
            "3000:\tnop".to_string(),
        ];
        assert!(follows_a_transfer_it_skipped(&w2));
    }
}











