//! Gadget：一个可用 one-gadget 的偏移、效果与约束；含 1.10.0 的评分与展示。
//!
//! 对齐 one_gadget v1.10.0 `Gadget::Gadget`：
//! - score = 各约束概率连乘
//! - inspect 的 writable 合并展示（`address(es) X is/are writable`）
//! - CLI 的 level 过滤：score >= 0.2 分区 + take_until(3)

use crate::lambda::{hex, parse_int_str};
use serde::{Deserialize, Serialize};

/// 一个 gadget。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gadget {
    pub offset: u64,
    pub effect: String,
    pub constraints: Vec<String>,
    /// 输出基址（--base）。
    #[serde(skip)]
    pub base: u64,
}

impl Gadget {
    pub fn new(offset: u64, effect: String, constraints: Vec<String>) -> Self {
        Gadget { base: 0, offset, effect, constraints }
    }

    /// base + offset。
    pub fn value(&self) -> u64 {
        self.base + self.offset
    }

    /// 成功概率（连乘）。
    pub fn score(&self) -> f64 {
        self.constraints.iter().map(|c| calculate_score(c)).product::<f64>()
    }

    /// pretty 输出（对齐 1.10.0 inspect，无着色）。
    /// inspect 返回 `...constraints\n`，CLI 用 join("\n") 拼接 → 块间空行。
    pub fn to_pretty(&self) -> String {
        let mut s = format!("{} {}\n", hex(self.value() as i64), self.effect);
        if !self.constraints.is_empty() {
            s += "constraints:\n  ";
            s += &merge_constraints(&self.constraints).join("\n  ");
            s += "\n";
        }
        s
    }
}

/// level 过滤（refine_gadgets + take_until）。
pub fn refine_gadgets(gadgets: Vec<Gadget>, level: u32) -> Vec<Gadget> {
    if gadgets.is_empty() || level > 0 {
        return gadgets;
    }
    let (high, low): (Vec<_>, Vec<_>) = gadgets.into_iter().partition(|g| g.score() >= 0.2);
    let pool = if high.is_empty() { low } else { high };
    take_until(pool, 3)
}

/// `Fetcher.from_file` 的 trim_gadgets：去重 → 按约束数升序 → 剔除约束超集
/// → 按 offset 排序（最终输出顺序的权威来源）。
pub fn trim_gadgets(gadgets: Vec<Gadget>) -> Vec<Gadget> {
    // uniq(&:constraints)：约束列表完全相同只留首个
    let mut uniq: Vec<Gadget> = Vec::new();
    for g in gadgets {
        if !uniq.iter().any(|u| u.constraints == g.constraints) {
            uniq.push(g);
        }
    }
    // sort_by { constraints.size }（稳定排序）
    uniq.sort_by_key(|g| g.constraints.len());
    // 保留不是前面任何 gadget 约束子集的（前 j 的约束 ⊆ 当前 → 丢弃当前）
    let mut res: Vec<Gadget> = Vec::new();
    for (i, g) in uniq.iter().enumerate() {
        let subsumed = (0..i).any(|j| {
            uniq[j].constraints.iter().all(|c| g.constraints.contains(c))
        });
        if !subsumed {
            res.push(g.clone());
        }
    }
    res.sort_by_key(|g| g.offset);
    res
}

/// 保留 score 前 count 名（同分全保留）。
fn take_until(ary: Vec<Gadget>, count: usize) -> Vec<Gadget> {
    if ary.len() <= count {
        return ary;
    }
    let mut sorted: Vec<f64> = ary.iter().map(|g| g.score()).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let threshold = sorted[ary.len() - count];
    ary.into_iter().filter(|g| g.score() >= threshold).collect()
}

// ---------- 评分（1.10.0 calculate_score） ----------

fn calculate_score(expr: &str) -> f64 {
    if expr.contains(" || ") {
        return expr.split(" || ").map(calculate_score).fold(f64::MIN, f64::max);
    }
    if expr.contains(" & 0xf") {
        return 0.95;
    }
    if expr.contains("GOT address") {
        return 0.9;
    }
    if let Some(id) = expr.strip_prefix("writable: ") {
        return writable_score(id);
    }
    if let Some(id) = expr.strip_suffix(" == NULL") {
        return null_score(id);
    }
    if let Some(id) = expr.strip_suffix(" <= 0") {
        return null_score(id);
    }
    if expr.ends_with("is a valid argv") || expr.ends_with("is a valid envp") {
        return 0.2;
    }
    // 未归类：1.10.0 case 不命中返回 nil → reduce 语义视作 1.0
    1.0
}

fn writable_score(identity: &str) -> f64 {
    if identity.starts_with('[') {
        return 0.81;
    }
    let (base, _) = split_base(identity);
    if stack_register(&base) { 0.95 } else { 0.81 }
}

fn null_score(identity: &str) -> f64 {
    let id = strip_cast(identity);
    // 1.10.0 Lambda.parse 的结构（权威验证）：
    //   "[rbp-0x70]"     → deref=1, obj="rbp"（字符串栈名 → extra 0）→ 0.9
    //   "[[rbp-0x70]]"   → deref=2, obj="rbp"（字符串栈名）→ 0.9^2
    //   "[[rax]]"        → deref=2, obj="rax"（非栈）→ 0.9^3
    //   "[[rsp+0x38]+0x4]" → deref=1, obj 是 Lambda（imm 折套新层）→ 0.9^2
    // 规则：剥掉**一层**最外括号得内层表达式 E：
    //   - E = "name±imm"（无括号）→ obj 是字符串 name，deref = 总括号数 - 1
    //     …不对：deref 就是 parse 出的层数。直接重构：
    //   - E 无括号且无尾随 imm（`[name+imm]`）→ deref=1, obj=name
    //   - E 无括号有尾随 imm（`[name]+imm` 或 `[[X]+imm]` 外层）
    //     → deref=1, obj=Lambda(E)（嵌套）
    //   - E 有括号无尾 imm（`[[X]]`）→ deref=2, obj=X 的字符串名
    // 这里用 parse 语义逐步降层实现。
    let p = parse_shape(&id);
    if p.deref == 0 {
        return if p.imm == 0 { 0.9 } else { 0.1 };
    }
    let extra = if p.obj_is_stack_string { 0 } else { 1 };
    0.9f64.powi(p.deref + extra)
}

/// 1.10.0 `Lambda.parse` 的结构形状。
struct Shape {
    deref: i32,
    imm: i64,
    /// obj 是字符串且为栈寄存器名。
    obj_is_stack_string: bool,
}

/// 模拟 Ruby parse（权威语义，逐字对齐 lambda.rb 118-136 行）：
/// ```ruby
/// if arg[0] == '['
///   ridx = arg.rindex(']'); immi = parse(arg[ridx+1..])
///   lm = parse(arg[1...ridx]).deref
///   lm += immi unless immi.zero?   # deref>0 时 + 会套新层（obj=旧整体, deref=0）
/// end
/// base, disp = mem_obj(arg); obj = predefined[base] || Lambda.new(base)
/// obj += disp unless disp.zero?    # deref==0 时 imm 直接折入
/// ```
/// 直接递归实现：
/// - `s` 不以 `[` 开头 → (base, disp) 拆分，deref=0
/// - `s = [E]`（尾无 imm）→ parse(E) 的形状 + deref1
/// - `s = [E]±imm` → parse(E) 得 L（deref≥1）；套新层：obj=Lambda、
///   deref=0+1=1（**归一**）、imm=tail —— 即 `[[rsp+0x38]+0x4]` deref=1
fn parse_shape(s: &str) -> Shape {
    if !s.starts_with('[') {
        let (base, imm) = split_base(s);
        return Shape { deref: 0, imm, obj_is_stack_string: stack_register(&base) };
    }
    // rindex(']')：尾 imm 在其后
    let ridx = s.rfind(']').unwrap();
    let inner = &s[1..ridx];
    let tail = &s[ridx + 1..];
    let tail_imm = if tail.is_empty() { 0 } else { parse_int_str(tail).unwrap_or(0) };
    let sub = parse_shape(inner);
    if tail_imm == 0 {
        // lm = parse(inner).deref —— 透传 + 1 层
        Shape { deref: sub.deref + 1, imm: sub.imm, obj_is_stack_string: sub.obj_is_stack_string }
    } else {
        // Ruby `lm += imm`（inner 有 deref ≥1 → 套新层：obj=旧整体, deref=0, imm=tail）
        // 之后外层 `.deref` +1 —— 套层后的形状：deref 0、obj 非 string
        Shape { deref: 0, imm: tail_imm, obj_is_stack_string: false }
    }
}

/// `rbp-0x50` → ("rbp", -0x50)；嵌套括号取最外层基。
fn split_base(identity: &str) -> (String, i64) {
    let s = identity.trim();
    // 取最外层 [ ... ] 的内层
    let s = if s.starts_with('[') {
        s[1..s.rfind(']').unwrap_or(s.len() - 1)].to_string()
    } else {
        s.to_string()
    };
    if let Some(v) = parse_int_str(&s) {
        return (String::new(), v);
    }
    if let Some(pos) = s.find(['+', '-']) {
        let base = s[..pos].to_string();
        let imm = parse_int_str(&s[pos..]).unwrap_or(0);
        (base, imm)
    } else {
        (s.to_string(), 0)
    }
}

fn strip_cast(s: &str) -> String {
    if s.starts_with("(s") || s.starts_with("(u") {
        if let Some(end) = s.find(')') {
            if (3..=5).contains(&end) {
                return s[end + 1..].to_string();
            }
        }
    }
    s.to_string()
}

fn stack_register(reg: &str) -> bool {
    matches!(reg, "esp" | "ebp" | "rsp" | "rbp" | "sp" | "x29")
}

/// writable 合并展示（merge_constraints）。
fn merge_constraints(cons: &[String]) -> Vec<String> {
    let key = "writable: ";
    let (w_cons, normal): (Vec<_>, Vec<_>) = cons.iter().partition(|c| c.starts_with(key));
    if w_cons.is_empty() {
        return normal.into_iter().cloned().collect();
    }
    let ws: Vec<String> = w_cons.iter().map(|c| c[key.len()..].to_string()).collect();
    let mut out = vec![format!(
        "address{} {} {} writable",
        if ws.len() > 1 { "es" } else { "" },
        ws.join(", "),
        if ws.len() > 1 { "are" } else { "is" },
    )];
    out.extend(normal.into_iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_products() {
        let g = Gadget::new(0x100, "e".into(), vec!["rsp & 0xf == 0".into()]);
        assert!((g.score() - 0.95).abs() < 1e-9);
        let g2 = Gadget::new(0x100, "e".into(), vec!["rax == NULL".into()]);
        assert!((g2.score() - 0.9).abs() < 1e-9);
        let g3 = Gadget::new(0x100, "e".into(), vec!["[rax] == NULL".into()]);
        assert!((g3.score() - 0.81).abs() < 1e-9); // 0.9^2
        let g4 = Gadget::new(0x100, "e".into(), vec!["[rbp-0x70] == NULL".into()]);
        assert!((g4.score() - 0.9).abs() < 1e-9); // 栈基 deref1
    }

    #[test]
    fn test_merge_constraints() {
        let out = merge_constraints(&["writable: rsp+0x70".into(), "rsp & 0xf == 0".into()]);
        assert_eq!(out[0], "address rsp+0x70 is writable");
        let out2 = merge_constraints(&[
            "writable: rbp-0x48".into(),
            "writable: rbx+0xe0".into(),
        ]);
        assert_eq!(out2[0], "addresses rbp-0x48, rbx+0xe0 are writable");
    }

    #[test]
    fn test_null_score_cast() {
        let s = calculate_score("(u16)[rbp] == NULL");
        assert!((s - 0.9).abs() < 1e-9);
        let s2 = calculate_score("(s32)[[rsp+0x38]+0x4] <= 0");
        assert!((s2 - 0.81).abs() < 1e-9);
    }

    #[test]
    fn test_or_max() {
        let s = calculate_score("rdi == NULL || writable: rdi");
        assert!((s - 0.9).abs() < 1e-9);
    }
}
