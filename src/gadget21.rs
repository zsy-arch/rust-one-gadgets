//! 2.1.1 管线的 gadget 后处理（master gadget.rb + fetchers.rb 语义）。
//!
//! 与 1.10.0（crate::gadget）的差异：
//! - `prune_settled`：构造时自剪约束（ruled-out-null/已定非空/已定比较/已述可读）
//! - score：栈对齐 0.95、MASKED_ZERO 0.92、null 0.9/0.1/0.9^(deref+base) 等
//! - trim：sort [size, -offset, constraints] → uniq → met_by 支配剔除 → 按 offset 取最易
//! - level ≥ RAW_LEVEL：all_gadgets（保 (offset, constraints) 全体）

use crate::abi::{self, AbiArch};
use crate::gadget::Gadget;
use crate::lambda::parse_int_str;

const DISJUNCTION: &str = " || ";
const PAGE_SIZE: i64 = 0x1000;

/// master Fetchers::RAW_LEVEL：≥ 该 level 保全部 gadget。
pub const RAW_LEVEL: u32 = 2;

/// 所有架构寄存器名（master REGISTER_NAMES = ABI.all）。
fn register_names() -> &'static [&'static str] {
    static NAMES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        let mut v: Vec<&'static str> = Vec::new();
        for arch in [
            AbiArch::Amd64,
            AbiArch::I386,
            AbiArch::Aarch64,
            AbiArch::Arm,
            AbiArch::Riscv64,
            AbiArch::Mips,
        ] {
            for r in abi::registers(arch) {
                if !v.iter().any(|&s| s == r) {
                    v.push(Box::leak(r.into_boxed_str()));
                }
            }
        }
        v
    })
}

fn is_register_name(tok: &str) -> bool {
    register_names().contains(&tok)
}

// ---------- prune_settled ----------

/// 构造期约束自剪（master Gadget#initialize），循环到不动点。
pub fn prune_settled(cons: Vec<String>) -> Vec<String> {
    let mut cons = cons;
    loop {
        let settled = drop_stated_readable(&drop_settled_comparison(&drop_settled_non_null(
            &drop_ruled_out_null(&cons),
        )));
        if settled == cons {
            return cons;
        }
        cons = settled;
    }
}

/// 无析取（outright 成立）的约束。
fn unconditional(cons: &[String]) -> Vec<&str> {
    cons.iter().map(|c| c.as_str()).filter(|c| !c.contains(DISJUNCTION)).collect()
}

/// cons 是否要求 identity 为映射内存。
fn mapped(cons: &[String], identity: &str) -> bool {
    let deref = format!("[{identity}]");
    let near_prefix = format!("[{identity}");
    unconditional(cons).iter().any(|con| {
        if con == &format!("readable: {identity}") || con == &format!("writable: {identity}") {
            return true;
        }
        if con.contains(&deref) {
            return true;
        }
        // [identity±0x..] 且 |off| < PAGE_SIZE（近邻解引用 → 同页必映射）
        let mut rest = *con;
        while let Some(i) = rest.find(&near_prefix) {
            let after = &rest[i + near_prefix.len()..];
            if let Some(close) = after.find(']') {
                if let Some(v) = parse_int_str(after[..close].trim()) {
                    if v.abs() < PAGE_SIZE {
                        return true;
                    }
                }
            }
            rest = &rest[i + 1..];
        }
        false
    })
}

/// 多选项约束里剔除「要求已映射地址为 NULL」的选项；全剔则保留原样（不可能性不归本层管）。
fn drop_ruled_out_null(cons: &[String]) -> Vec<String> {
    cons.iter()
        .map(|con| {
            let options: Vec<&str> = con.split(DISJUNCTION).collect();
            if options.len() == 1 {
                return con.clone();
            }
            let kept: Vec<&str> = options
                .iter()
                .copied()
                .filter(|opt| match opt.strip_suffix(" == NULL") {
                    Some(id) => !mapped(cons, id),
                    None => true,
                })
                .collect();
            if kept.is_empty() { con.clone() } else { kept.join(DISJUNCTION) }
        })
        .collect()
}

/// 剔除「已映射地址非 NULL」约束（cast 过的不算）。
fn drop_settled_non_null(cons: &[String]) -> Vec<String> {
    cons.iter()
        .filter(|con| match con.strip_suffix(" != NULL").or_else(|| con.strip_suffix(" != 0x0")) {
            Some(id) => id.starts_with("(s") || id.starts_with("(u") || !mapped(cons, id),
            None => true,
        })
        .cloned()
        .collect()
}

/// 比较约束（cast? lhs op rhs；rhs 为 NULL 或数字字面量）。
struct Comparison<'a> {
    sign: Option<char>,
    bits: Option<u32>,
    lhs: &'a str,
    op: &'a str,
    rhs: &'a str,
}

/// master COMPARISON：`\A(?:\(([su])(\d+)\))?(.+?) (==|!=|<=|>=|<|>) (NULL|-?(?:0x..|\d+))\z`
fn parse_comparison(con: &str) -> Option<Comparison<'_>> {
    for op in ["==", "!=", "<=", ">=", "<", ">"] {
        let needle = format!(" {op} ");
        let Some(i) = con.find(&needle) else { continue };
        let (lhs_raw, rest) = con.split_at(i);
        let rhs = &rest[needle.len()..];
        if rhs != "NULL" && parse_int_str(rhs).is_none() {
            return None;
        }
        // lhs 可带 (sN)/(uN) cast 前缀
        let (cast, lhs) = if lhs_raw.starts_with('(') && lhs_raw.len() > 4 {
            match lhs_raw.find(')') {
                Some(e) if matches!(lhs_raw.as_bytes()[1], b's' | b'u') => {
                    (Some((lhs_raw.as_bytes()[1] as char, lhs_raw[2..e].parse().ok())), &lhs_raw[e + 1..])
                }
                _ => (None, lhs_raw),
            }
        } else {
            (None, lhs_raw)
        };
        let (sign, bits) = match cast {
            Some((s, b)) => (Some(s), b),
            None => (None, None),
        };
        return Some(Comparison { sign, bits, lhs: lhs.trim(), op, rhs });
    }
    None
}

/// 剔除已被钉死值回答的比较（只有未 cast 的 == 钉整个值；不成立的保留）。
fn drop_settled_comparison(cons: &[String]) -> Vec<String> {
    let mut pinned: Vec<(&str, i64)> = Vec::new();
    for con in unconditional(cons) {
        if let Some(c) = parse_comparison(con) {
            if c.sign.is_none() && c.op == "==" && !pinned.iter().any(|(l, _)| *l == c.lhs) {
                pinned.push((c.lhs, literal_value(c.rhs)));
            }
        }
    }
    if pinned.is_empty() {
        return cons.to_vec();
    }
    cons.iter()
        .filter(|con| {
            let Some(c) = parse_comparison(con) else { return true };
            if c.sign.is_none() && c.op == "==" {
                return true;
            }
            match pinned.iter().find(|(l, _)| *l == c.lhs) {
                Some((_, v)) => !comparison_holds(*v, &c),
                None => true,
            }
        })
        .cloned()
        .collect()
}

fn literal_value(literal: &str) -> i64 {
    if literal == "NULL" { 0 } else { parse_int_str(literal).unwrap_or(0) }
}

fn comparison_holds(value: i64, c: &Comparison) -> bool {
    let v = match (c.sign, c.bits) {
        (Some(s), Some(b)) => as_cast(value, s, b),
        _ => value,
    };
    let r = literal_value(c.rhs);
    match c.op {
        "==" => v == r,
        "!=" => v != r,
        "<=" => v <= r,
        ">=" => v >= r,
        "<" => v < r,
        ">" => v > r,
        _ => true,
    }
}

fn as_cast(value: i64, sign: char, bits: u32) -> i64 {
    let mask: i64 = (1i64 << bits) - 1;
    let low = value & mask;
    if sign == 's' && low >= 1i64 << (bits - 1) { low - (1i64 << bits) } else { low }
}

/// 剔除已被 outright 解引用声明的 readable（只认地址本身，近邻不算）。
fn drop_stated_readable(cons: &[String]) -> Vec<String> {
    cons.iter()
        .filter(|con| match con.strip_prefix("readable: ") {
            Some(identity) => !unconditional(cons).iter().any(|other| other.contains(&format!("[{identity}]"))),
            None => true,
        })
        .cloned()
        .collect()
}

// ---------- score ----------

/// 2.1.1 score：`constraints.reduce(1.0) { _1 * calculate_score(_2) }`。
pub fn score(g: &Gadget) -> f64 {
    g.constraints.iter().map(|c| calculate_score(c)).product::<f64>()
}

/// `A & B` 拆分（两侧均非空、无括号）；返回 (lhs, mask)。
fn split_masked(lhs: &str) -> Option<(&str, &str)> {
    let body = lhs.strip_prefix('(').and_then(|b| b.strip_suffix(')')).unwrap_or(lhs);
    if body.contains('(') || body.contains(')') {
        return None;
    }
    let i = body.find(" & ")?;
    let (l, r) = (&body[..i], &body[i + 3..]);
    if l.is_empty() || r.is_empty() {
        return None;
    }
    Some((l, r))
}

/// MASKED_ZERO：`\A\(?[^()]+? & ~?(?:0x..|\d+)\)? == (?:NULL|0x0+)\z`（掩码必须是数字）。
fn masked_zero(expr: &str) -> bool {
    let Some(i) = expr.find(" == ") else { return false };
    let rhs = &expr[i + 4..];
    if !(rhs == "NULL" || is_zero_hex(rhs)) {
        return false;
    }
    match split_masked(&expr[..i]) {
        Some((_, mask)) => numeric_mask(mask),
        None => false,
    }
}

fn is_zero_hex(s: &str) -> bool {
    match s.strip_prefix("0x") {
        Some(h) => !h.is_empty() && h.chars().all(|c| c == '0'),
        None => false,
    }
}

/// `~?数字` 掩码。
fn numeric_mask(mask: &str) -> bool {
    let m = mask.strip_prefix('~').unwrap_or(mask);
    parse_int_str(m).is_some()
}

/// MASKED：比较左侧带掩码（掩码可为寄存器等任意无括号 token）。
fn masked_compare(expr: &str) -> bool {
    for op in ["==", "!=", "<=", ">=", "<", ">"] {
        let needle = format!(" {op} ");
        if let Some(i) = expr.find(&needle) {
            return split_masked(&expr[..i]).is_some();
        }
    }
    false
}

/// 栈对齐：`\A<sp-reg> & 0xf == 0x[0-9a-f]+\z`。
fn stack_alignment(expr: &str) -> bool {
    let Some(i) = expr.find(" & 0xf == 0x") else { return false };
    let reg = &expr[..i];
    let rest = &expr[i + " & ".len()..];
    let Some((_, val)) = rest.split_once(" == ") else { return false };
    if reg.is_empty() || reg.contains(char::is_whitespace) {
        return false;
    }
    let hex_ok = val.len() > 2 && val.starts_with("0x") && val[2..].chars().all(|c| c.is_ascii_hexdigit());
    hex_ok && abi::is_stack_register(reg)
}

fn deref_depth(identity: &str) -> usize {
    identity.chars().take_while(|&c| c == '[').count()
}

/// identity 首个命中的寄存器 token（master base_register：scan(/\w+/).find）。
fn base_register(identity: &str) -> Option<String> {
    let mut tok = String::new();
    for c in identity.chars().chain(std::iter::once('.')) {
        if c.is_alphanumeric() || c == '_' {
            tok.push(c);
        } else {
            if is_register_name(&tok) {
                return Some(tok);
            }
            tok.clear();
        }
    }
    None
}

fn bare_register(identity: &str) -> bool {
    Some(identity.to_string()) == base_register(identity)
}

fn calculate_relation_score(expr: &str) -> f64 {
    let Some((op, lhs)) = ["==", "!=", "<=", ">=", "<", ">"].iter().find_map(|op| {
        let needle = format!(" {op} ");
        expr.find(&needle).map(|i| (*op, &expr[..i]))
    }) else {
        return 1.0;
    };
    let lhs = strip_cast(lhs.trim());
    let base = if op == "==" { 0.4 } else { 0.6 };
    base * 0.9f64.powi(deref_depth(lhs) as i32)
}

fn calculate_score(expr: &str) -> f64 {
    if expr.contains(DISJUNCTION) {
        return expr.split(DISJUNCTION).map(calculate_score).fold(f64::MIN, f64::max);
    }
    if stack_alignment(expr) {
        return 0.95;
    }
    if masked_zero(expr) {
        return 0.92;
    }
    if masked_compare(expr) {
        return calculate_relation_score(expr);
    }
    if expr.contains("GOT address") {
        return 0.9;
    }
    if let Some(id) = expr.strip_prefix("writable: ") {
        return writable_score(id);
    }
    for suffix in [" == NULL", " == 0x0", " <= 0x0"] {
        if let Some(id) = expr.strip_suffix(suffix) {
            return null_score(id);
        }
    }
    if expr.starts_with("readable") || expr.ends_with("is a valid argv") || expr.ends_with("is a valid envp") {
        return 0.2;
    }
    if ["==", "!=", "<=", ">=", "<", ">"].iter().any(|op| expr.contains(&format!(" {op} "))) {
        return calculate_relation_score(expr);
    }
    1.0
}

fn writable_score(identity: &str) -> f64 {
    if deref_depth(identity) > 0 {
        return 0.81;
    }
    match base_register(identity) {
        Some(r) if abi::is_stack_register(&r) => 0.95,
        _ => 0.81,
    }
}

fn null_score(identity: &str) -> f64 {
    let id = strip_cast(identity);
    let depth = deref_depth(id);
    if depth == 0 {
        return if bare_register(id) { 0.9 } else { 0.1 };
    }
    let base = match base_register(id) {
        Some(r) if abi::is_stack_register(&r) => 0,
        _ => 1,
    };
    0.9f64.powi((depth + base) as i32)
}

fn strip_cast(s: &str) -> &str {
    if s.starts_with("(s") || s.starts_with("(u") {
        if let Some(e) = s.find(')') {
            return &s[e + 1..];
        }
    }
    s
}

// ---------- met_by / trim / level ----------

/// master met_by?：this 的每条约束都在 other 列表里，或其某一选项被 other outright 要求。
fn met_by(g: &Gadget, other: &Gadget) -> bool {
    g.constraints.iter().all(|con| {
        other.constraints.contains(con)
            || con.split(DISJUNCTION).any(|opt| other.constraints.iter().any(|c| c == opt))
    })
}

/// master Fetchers.trim_gadgets（level < RAW_LEVEL）。
pub fn trim_gadgets(gadgets: Vec<Gadget>) -> Vec<Gadget> {
    // 完全排序后再剔除：[size, -offset, constraints]（约束集相同的取最大 offset —— 离 call 最近）
    let mut sorted = gadgets;
    sorted.sort_by(|a, b| {
        a.constraints
            .len()
            .cmp(&b.constraints.len())
            .then(b.offset.cmp(&a.offset))
            .then(a.constraints.cmp(&b.constraints))
    });
    let mut uniq: Vec<Gadget> = Vec::new();
    for g in sorted {
        if !uniq.iter().any(|u| u.constraints == g.constraints) {
            uniq.push(g);
        }
    }
    // 支配剔除：g 被更早（更易满足）的 gadget 完全覆盖则丢弃
    let mut res: Vec<Gadget> = Vec::new();
    for (i, g) in uniq.iter().enumerate() {
        if !(0..i).any(|j| met_by(&uniq[j], g)) {
            res.push(g.clone());
        }
    }
    // 同 offset 多分支方向：保留约束最少的一个，按 offset 升序
    let mut by_offset: std::collections::BTreeMap<u64, Gadget> = std::collections::BTreeMap::new();
    for g in res {
        by_offset
            .entry(g.offset)
            .and_modify(|e| {
                if g.constraints.len() < e.constraints.len() {
                    *e = g.clone();
                }
            })
            .or_insert(g);
    }
    by_offset.into_values().collect()
}

/// Apple/macOS 系统 `qsort_r`（Libc `stdlib/FreeBSD/qsort.c` 的 Bentley–McIlroy
/// 快排 + 深度耗尽 heapsort）逐行移植。macOS 上 CRuby 的 `ruby_qsort` 经
/// `HAVE_BSD_QSORT_R` 直调系统 `qsort_r`（bundled qs6 不参与），`sort_by`
/// 非原始键（如 master 的 `[offset, size]` 数组键）平局顺序即由它决定；
/// 稳定排序与 qs6 均无法复现。C 侧 swaptype 只影响字节搬运方式、不影响
/// 置换，故此处以整元素 swap 表达。
pub(crate) fn apple_qsort_r<T: Clone>(v: &mut [T], cmp: &mut impl FnMut(&T, &T) -> i32) {
    let n = v.len();
    if n <= 1 {
        return;
    }
    // DEPTH(n) = 2 * (flsl(n) - 1)
    let depth = 2 * (64 - (n as u64).leading_zeros() as i32 - 1);
    qsort_rec(v, 0, n, cmp, depth);
}

/// FreeBSD `med3`：三取中（比较次序逐字对齐 C 宏）。
fn med3<T>(v: &[T], a: usize, b: usize, c: usize, cmp: &mut impl FnMut(&T, &T) -> i32) -> usize {
    if cmp(&v[a], &v[b]) < 0 {
        if cmp(&v[b], &v[c]) < 0 {
            b
        } else if cmp(&v[a], &v[c]) < 0 {
            c
        } else {
            a
        }
    } else if cmp(&v[b], &v[c]) > 0 {
        b
    } else if cmp(&v[a], &v[c]) < 0 {
        a
    } else {
        c
    }
}

/// FreeBSD `_isort`：插入排序；`limit == 0` 不限交换次数，否则超限返回 false。
fn isort<T>(v: &mut [T], limit: usize, cmp: &mut impl FnMut(&T, &T) -> i32) -> bool {
    let mut cnt: usize = 0;
    for pm in 1..v.len() {
        let mut pl = pm;
        while pl > 0 && cmp(&v[pl - 1], &v[pl]) > 0 {
            v.swap(pl, pl - 1);
            if limit != 0 {
                cnt += 1;
                if cnt > limit {
                    return false;
                }
            }
            pl -= 1;
        }
    }
    true
}

/// FreeBSD `vecswap`。
fn vecswap<T>(v: &mut [T], mut a: usize, mut b: usize, n: usize) {
    for _ in 0..n {
        v.swap(a, b);
        a += 1;
        b += 1;
    }
}

/// FreeBSD `_qsort`（`I_AM_QSORT_R`，元素尺寸归一为 1）：区间 `[lo, lo+n)`。
fn qsort_rec<T: Clone>(
    v: &mut [T],
    lo: usize,
    mut n: usize,
    cmp: &mut impl FnMut(&T, &T) -> i32,
    mut depth: i32,
) {
    let mut lo = lo;
    'outer: loop {
        let mut swap_cnt = false;
        if {
            let d = depth;
            depth -= 1;
            d
        } <= 0
        {
            heapsort_r(&mut v[lo..lo + n], cmp);
            return;
        }
        if n <= 7 {
            isort(&mut v[lo..lo + n], 0, cmp);
            return;
        }
        // 伪中位数：小数组 3 采样，n > 40 用 9 采样
        let mut pl = lo;
        let mut pm = lo + n / 2;
        let mut pn = lo + n - 1;
        if n > 40 {
            let d = n / 8;
            pl = med3(v, pl, pl + d, pl + 2 * d, cmp);
            pm = med3(v, pm - d, pm, pm + d, cmp);
            pn = med3(v, pn - 2 * d, pn - d, pn, cmp);
        }
        pm = med3(v, pl, pm, pn, cmp);

        v.swap(lo, pm);
        let mut pa = lo + 1;
        let mut pb = lo + 1;
        let mut pc = lo + n - 1;
        let mut pd = lo + n - 1;
        loop {
            while pb <= pc {
                let r = cmp(&v[pb], &v[lo]);
                if r > 0 {
                    break;
                }
                if r == 0 {
                    swap_cnt = true;
                    v.swap(pa, pb);
                    pa += 1;
                }
                pb += 1;
            }
            while pb <= pc {
                let r = cmp(&v[pc], &v[lo]);
                if r < 0 {
                    break;
                }
                if r == 0 {
                    swap_cnt = true;
                    v.swap(pc, pd);
                    pd -= 1;
                }
                pc -= 1;
            }
            if pb > pc {
                break;
            }
            v.swap(pb, pc);
            swap_cnt = true;
            pb += 1;
            pc -= 1;
        }
        let end = lo + n;
        let d1 = (pa - lo).min(pb - pa);
        vecswap(v, lo, pb - d1, d1);
        let d1 = (pd - pc).min(end - pd - 1);
        vecswap(v, pb, end - d1, d1);

        if !swap_cnt {
            let limit = 1 + n / 4;
            if isort(&mut v[lo..lo + n], limit, cmp) {
                return;
            }
        }
        let d1 = pb - pa;
        let d2 = pd - pc;
        if d1 <= d2 {
            if d1 > 1 {
                qsort_rec(v, lo, d1, cmp, depth);
            }
            if d2 > 1 {
                lo = end - d2;
                n = d2;
                continue 'outer;
            }
        } else {
            if d2 > 1 {
                qsort_rec(v, end - d2, d2, cmp, depth);
            }
            if d1 > 1 {
                n = d1;
                continue 'outer;
            }
        }
        return;
    }
}

/// FreeBSD `__heapsort_r`：1-indexed 堆以 0-indexed 切片表达（elem(k) = v[k-1]）。
fn heapsort_r<T: Clone>(v: &mut [T], cmp: &mut impl FnMut(&T, &T) -> i32) {
    let mut n = v.len();
    if n <= 1 {
        return;
    }
    // 建堆：CREATE，l 自 n/2 递减到 1
    let mut l = n / 2 + 1;
    loop {
        l -= 1;
        if l == 0 {
            break;
        }
        let mut par_i = l;
        loop {
            let mut child_i = par_i * 2;
            if child_i > n {
                break;
            }
            if child_i < n && cmp(&v[child_i - 1], &v[child_i]) < 0 {
                child_i += 1;
            }
            if cmp(&v[child_i - 1], &v[par_i - 1]) <= 0 {
                break;
            }
            v.swap(child_i - 1, par_i - 1);
            par_i = child_i;
        }
    }
    // 逐个取堆顶放终位，SELECT 回插被顶出的 k
    while n > 1 {
        let k = v[n - 1].clone();
        v[n - 1] = v[0].clone();
        n -= 1;
        let mut par_i: usize = 1;
        loop {
            let mut child_i = par_i * 2;
            if child_i > n {
                break;
            }
            if child_i < n && cmp(&v[child_i - 1], &v[child_i]) < 0 {
                child_i += 1;
            }
            v[par_i - 1] = v[child_i - 1].clone();
            par_i = child_i;
        }
        loop {
            let child_i = par_i;
            let parent = child_i / 2;
            if child_i == 1 || cmp(&k, &v[parent - 1]) < 0 {
                v[child_i - 1] = k.clone();
                break;
            }
            v[child_i - 1] = v[parent - 1].clone();
            par_i = parent;
        }
    }
}

/// master Fetchers.all_gadgets（level ≥ RAW_LEVEL）：保 (offset, constraints) 全体。
pub fn all_gadgets(gadgets: Vec<Gadget>) -> Vec<Gadget> {
    let mut uniq: Vec<Gadget> = Vec::new();
    for g in gadgets {
        if !uniq.iter().any(|u| u.offset == g.offset && u.constraints == g.constraints) {
            uniq.push(g);
        }
    }
    // master sort_by [offset, size]（macOS 经系统 qsort_r 的平局序）
    apple_qsort_r(&mut uniq, &mut |a, b| match a.offset.cmp(&b.offset) {
        std::cmp::Ordering::Equal => {
            (a.constraints.len() as i64).cmp(&(b.constraints.len() as i64)) as i32
        }
        o => o as i32,
    });
    uniq
}

/// master Fetchers.for_level。
pub fn for_level(gadgets: Vec<Gadget>, level: u32) -> Vec<Gadget> {
    if level >= RAW_LEVEL { all_gadgets(gadgets) } else { trim_gadgets(gadgets) }
}

/// master one_gadget.rb refine_gadgets（level 0 才过滤）。
pub fn refine_gadgets(gadgets: Vec<Gadget>, level: u32) -> Vec<Gadget> {
    if gadgets.is_empty() || level > 0 {
        return gadgets;
    }
    let (high, low): (Vec<_>, Vec<_>) = gadgets.into_iter().partition(|g| score(g) >= 0.2);
    let pool = if high.is_empty() { low } else { high };
    take_until(pool, 3)
}

/// master take_until：count 个最好 + 与末位并列的全保留。
fn take_until(ary: Vec<Gadget>, count: usize) -> Vec<Gadget> {
    if ary.len() <= count {
        return ary;
    }
    let mut scores: Vec<f64> = ary.iter().map(score).collect();
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let threshold = scores[ary.len() - count];
    ary.into_iter().filter(|g| score(g) >= threshold).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(offset: u64, cons: &[&str]) -> Gadget {
        Gadget::new(offset, "e".into(), cons.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_prune_settled() {
        // master drop_ruled_out_null 例：writable: r8 → r8 已映射，r8 == NULL 选项剔除
        assert_eq!(
            prune_settled(vec!["writable: r8".into(), "r8 == NULL || (u16)[r8] == 0x0".into()]),
            vec!["writable: r8".to_string(), "(u16)[r8] == 0x0".to_string()]
        );
        // drop_stated_readable：[x1] outright 解引用已含可读性
        assert_eq!(
            prune_settled(vec!["readable: x1".into(), "[x1] == 0x0".into()]),
            vec!["[x1] == 0x0".to_string()]
        );
        // drop_settled_comparison：r0 钉 0 → (u32)0 <= 0xfffff000 不成立？0 <= 0xfffff000 成立 → 剔除
        assert_eq!(
            prune_settled(vec!["r0 == NULL".into(), "(u32)r0 <= 0xfffff000".into()]),
            vec!["r0 == NULL".to_string()]
        );
        // mapped? 近邻解引用：[r8+0x10] → r8 映射 → r8 != NULL 剔除
        assert_eq!(
            prune_settled(vec!["r8 != NULL".into(), "[r8+0x10] == 0x1".into()]),
            vec!["[r8+0x10] == 0x1".to_string()]
        );
    }

    #[test]
    fn test_score_21() {
        assert!((calculate_score("rsp & 0xf == 0x0") - 0.95).abs() < 1e-9);
        assert!((calculate_score("(x0 & 0xf000) == 0x0") - 0.92).abs() < 1e-9);
        assert!((calculate_score("x0 & 0xf == 0x0") - 0.92).abs() < 1e-9);
        // 寄存器掩码不是 MASKED_ZERO，是 MASKED → relation 0.4
        assert!((calculate_score("(x0 & x1) == 0x0") - 0.4).abs() < 1e-9);
        assert!((calculate_score("x1 == 0x1") - 0.4).abs() < 1e-9);
        assert!((calculate_score("(u64)x0 >= 0x400") - 0.6).abs() < 1e-9);
        assert!((calculate_score("writable: x29+0x40") - 0.95).abs() < 1e-9); // x29 是 stack_register
        assert!((calculate_score("writable: sp+0x50") - 0.95).abs() < 1e-9);
        assert!((calculate_score("x0 == NULL") - 0.9).abs() < 1e-9);
        assert!((calculate_score("x0+0x10 == NULL") - 0.1).abs() < 1e-9);
        assert!((calculate_score("[sp+0x70] == NULL") - 0.9).abs() < 1e-9);
        assert!((calculate_score("[x21] == NULL") - 0.81).abs() < 1e-9);
        assert!((calculate_score("readable: x1") - 0.2).abs() < 1e-9);
        assert!(
            (calculate_score("x1 == NULL || {\"/bin/sh\", x1, NULL} is a valid argv") - 0.9).abs() < 1e-9
        );
    }

    #[test]
    fn test_met_by_units() {
        let a = g(0x100, &["x0 == NULL"]);
        let b = g(0x200, &["x0 == NULL", "writable: x29+0x40"]);
        assert!(met_by(&a, &b), "a should be met by b");
        assert!(!met_by(&b, &a));
    }

    #[test]
    fn test_trim_met_by() {
        // b 的约束集包含 a 的全部 → met_by(a, b) → b 丢弃
        let a = g(0x100, &["x0 == NULL"]);
        let b = g(0x200, &["x0 == NULL", "writable: x29+0x40"]);
        let out = trim_gadgets(vec![b, a]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset, 0x100);
        // master probe：trim([c,d]) 保留两个（sorted [d,c]，c.met_by?(d) 但 c 在后不剔 d）
        let c = g(0x300, &["x0 == NULL || [x0] == 0x0"]);
        let d = g(0x400, &["[x0] == 0x0"]);
        let out = trim_gadgets(vec![c.clone(), d.clone()]);
        assert_eq!(out.len(), 2);
        assert!(met_by(&c, &d), "c 的析取可被 d 的 outright 满足");
    }

    #[test]
    fn test_take_until_ties() {
        // 并列分全保留
        let gs = vec![g(1, &["x0 == NULL"]), g(2, &["x1 == NULL"]), g(3, &["x2 == NULL"])];
        let out = take_until(gs, 2);
        assert_eq!(out.len(), 3);
    }
}

#[cfg(test)]
mod qsort_tests {
    use super::*;

    /// 与 macOS 系统 qsort_r（ruby 4.0.7 sort_by 数组键路径的实际后端）
    /// 逐例对齐的置换 fixture：n|keys|expected-permutation。
    #[test]
    fn test_apple_qsort_r_permutations() {
        let fixtures = include_str!("../tests/qsort_fixtures.txt");
        let mut cases = 0;
        for line in fixtures.lines().filter(|l| !l.trim().is_empty()) {
            let (n_s, keys_s, perm_s) = {
                let mut it = line.splitn(3, '|');
                (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
            };
            let n: usize = n_s.parse().unwrap();
            let keys: Vec<i64> = keys_s.split(',').map(|x| x.parse().unwrap()).collect();
            let expected: Vec<usize> = perm_s.split(',').map(|x| x.parse().unwrap()).collect();
            assert_eq!(keys.len(), n);
            // pairs (key, original_index) → qsort by key only
            let mut pairs: Vec<(i64, usize)> = keys.iter().copied().zip(0..).collect();
            apple_qsort_r(&mut pairs, &mut |a, b| {
                match (a.0).cmp(&b.0) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Greater => 1,
                    std::cmp::Ordering::Equal => 0,
                }
            });
            let got: Vec<usize> = pairs.iter().map(|p| p.1).collect();
            assert_eq!(got, expected, "case n={n} keys={keys_s}");
            cases += 1;
        }
        assert!(cases > 20, "fixtures loaded: {cases}");
    }

    #[test]
    fn test_apple_qsort_r_sortedness() {
        // 不变量：任意输入排序后键非降，且为输入的一个置换
        let mut seed = 0x2545F4914F6CDD1Du64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for n in [0usize, 1, 2, 7, 8, 40, 41, 200] {
            let mut v: Vec<u64> = (0..n).map(|_| rand() % 97).collect();
            let mut sorted = v.clone();
            sorted.sort_unstable();
            apple_qsort_r(&mut v, &mut |a, b| match a.cmp(b) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            });
            assert_eq!(v, sorted, "n={n}");
        }
    }
}
