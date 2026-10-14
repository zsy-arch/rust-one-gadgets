//! Conditional / Constraints / TrackedMemory / DataProcessing 四个 mixin 的 Rust 整合
//!（对齐 master conditional.rb / constraints.rb / tracked_memory.rb / data_processing.rb）。

use super::processor::*;
use super::{hex, Lambda, Obj, Val};
use std::collections::HashMap;

// ================= Conditional =================

/// RELATION 表：cond → (op, signed?)。
pub fn relation(cond: &str) -> Option<(&'static str, Option<bool>)> {
    Some(match cond {
        "eq" => ("==", None),
        "ne" => ("!=", None),
        "ult" => ("<", Some(false)),
        "ule" => ("<=", Some(false)),
        "ugt" => (">", Some(false)),
        "uge" => (">=", Some(false)),
        "slt" => ("<", Some(true)),
        "sle" => ("<=", Some(true)),
        "sgt" => (">", Some(true)),
        "sge" => (">=", Some(true)),
        _ => return None,
    })
}

fn negate_op(op: &str) -> &'static str {
    match op {
        "==" => "!=",
        "!=" => "==",
        ">=" => "<",
        "<" => ">=",
        ">" => "<=",
        "<=" => ">",
        _ => unreachable!(),
    }
}

/// 零字面量（比较右侧的 0 一律 `0x0`）。
pub const ZERO: &str = "0x0";

impl State {
    /// record_compare。
    pub fn record_compare(&mut self, op: CmpOp, lhs: String, rhs: String) {
        self.flags = Some((op, lhs, rhs));
    }

    /// operand_str：寄存器→当前值文本；立即数→hex；其余原样。
    pub fn operand_str(&self, operand: &str) -> EmuResult<String> {
        if self.register(operand) {
            let v = self.registers.get(operand);
            if self.is_clobbered(&v) {
                return Err(EmuError::ClobberedRegister(operand.to_string()));
            }
            return Ok(value_str(&v));
        }
        match crate::lambda::parse_int_str(operand) {
            Some(v) => Ok(hex(v)),
            None => Ok(operand.to_string()),
        }
    }

    /// branch_on_compare：pending 分支。
    pub fn branch_on_compare(&mut self, cond: &str, target: u64) -> EmuResult<()> {
        let Some((op, lhs, rhs)) = self.flags.clone() else {
            return Err(EmuError::UnsupportedInstructionArgument("no compare".into()));
        };
        let Some((rel_op, sign)) = relation(cond) else {
            return Err(EmuError::UnsupportedInstructionArgument(format!("bad cond {cond}")));
        };
        if !op.ordered() && !matches!(cond, "eq" | "ne") {
            return Err(EmuError::UnsupportedInstructionArgument(
                "magnitude after equality-only compare".into(),
            ));
        }
        let bits = self.bits();
        self.pending = Some(PendingBranch {
            target,
            compare: Box::new(move |taken| compare_triple(op, lhs, rhs, rel_op, sign, taken, bits)),
        });
        Ok(())
    }

    /// branch_on_zero（cbz/cbnz、j*cxz）。
    pub fn branch_on_zero(&mut self, target: u64, operand: &str, negate: bool) -> EmuResult<()> {
        let reg = self.operand_str(operand)?;
        let hit = if negate { "!=" } else { "==" };
        let miss = if negate { "==" } else { "!=" };
        self.pending = Some(PendingBranch {
            target,
            compare: Box::new(move |taken| {
                (reg.clone(), if taken { hit.to_string() } else { miss.to_string() }, ZERO.to_string())
            }),
        });
        Ok(())
    }

    /// branch_on_bit（tbz/tbnz）。
    pub fn branch_on_bit(&mut self, target: u64, operand: &str, bit: u32, negate: bool) -> EmuResult<()> {
        let reg = self.operand_str(operand)?;
        let mask = hex((1i64 << bit) as u64 as i64);
        let hit = if negate { "!=" } else { "==" };
        let miss = if negate { "==" } else { "!=" };
        self.pending = Some(PendingBranch {
            target,
            compare: Box::new(move |taken| {
                (format!("({reg} & {mask})"), if taken { hit.to_string() } else { miss.to_string() }, ZERO.to_string())
            }),
        });
        Ok(())
    }

    /// resolve_pending_branch：以 cmd 的地址判定 taken。
    pub fn resolve_pending_branch(&mut self, cmd: &str) -> EmuResult<()> {
        let Some(p) = self.pending.take() else { return Ok(()) };
        let taken = addr_of_line(cmd) == p.target;
        let triple = (p.compare)(taken);
        let expr = triple.0.clone();
        self.constraints.push(CtItem::Cmp(triple.0, triple.1, triple.2));
        let comparisons = self.comparisons_on(&expr);
        if !satisfiable(&comparisons) {
            return Err(EmuError::InfeasiblePath(format!("cannot hold together: {expr}")));
        }
        Ok(())
    }

    pub fn comparisons_on(&self, expr: &str) -> Vec<(String, String, String)> {
        self.constraints
            .iter()
            .filter_map(|c| match c {
                CtItem::Cmp(l, o, r) if l == expr => Some((l.clone(), o.clone(), r.clone())),
                _ => None,
            })
            .collect()
    }
}

/// value_str：Int→hex；其余自身文本。
pub fn value_str(v: &Val) -> String {
    match v {
        Val::Int(i) => hex(*i),
        other => other.to_string(),
    }
}

/// compare_triple + render_sub/add/and。
fn compare_triple(
    op: CmpOp,
    lhs: String,
    rhs: String,
    rel_op: &str,
    sign: Option<bool>,
    taken: bool,
    bits: u32,
) -> (String, String, String) {
    let operator = if taken { rel_op } else { negate_op(rel_op) };
    let cast = match sign {
        Some(false) => format!("(u{bits})"),
        Some(true) => format!("(s{bits})"),
        None => String::new(),
    };
    match op {
        CmpOp::Sub => {
            let rhs = if rhs == "0" { ZERO.to_string() } else { rhs };
            (format!("{cast}{lhs}"), operator.to_string(), rhs)
        }
        CmpOp::Add => {
            // 无符号条件读 carry：lhs <= -rhs
            if sign == Some(false) {
                if let Some(v) = crate::lambda::parse_int_str(&rhs) {
                    if v != 0 {
                        let mask: i128 = if bits == 64 { u64::MAX as i128 } else { u32::MAX as i128 };
                        let moved = (-(v as i128)) & mask;
                        return (format!("{cast}{lhs}"), operator.to_string(), format!("0x{moved:x}"));
                    }
                }
            }
            (format!("{cast}({lhs} + {rhs})"), operator.to_string(), ZERO.to_string())
        }
        CmpOp::And => {
            let l = if lhs == rhs { lhs.clone() } else { format!("({lhs} & {rhs})") };
            (l, operator.to_string(), ZERO.to_string())
        }
    }
}

/// satisfiable?：区间交集（整数比较才参与）。
pub fn satisfiable(triples: &[(String, String, String)]) -> bool {
    let mut low: Option<i64> = None;
    let mut high: Option<i64> = None;
    let mut excluded: Vec<i64> = Vec::new();
    for (_e, op, rhs) in triples {
        let Some(v) = crate::lambda::parse_int_str(rhs) else { continue };
        match op.as_str() {
            "==" => {
                low = Some(low.unwrap_or(i64::MIN).max(v));
                high = Some(high.unwrap_or(i64::MAX).min(v));
            }
            "!=" => excluded.push(v),
            "<" => high = Some(high.unwrap_or(i64::MAX).min(v - 1)),
            "<=" => high = Some(high.unwrap_or(i64::MAX).min(v)),
            ">" => low = Some(low.unwrap_or(i64::MIN).max(v + 1)),
            ">=" => low = Some(low.unwrap_or(i64::MIN).max(v)),
            _ => {}
        }
    }
    if let (Some(l), Some(h)) = (low, high) {
        if l > h || (l == h && excluded.contains(&l)) {
            return false;
        }
    }
    true
}

// ================= TrackedMemory =================

impl State {
    /// get_corresponding_stack。
    pub fn stack_of(&self, base: &str) -> Option<&HashMap<i64, Val>> {
        // base 是寄存器名或已跟踪 base 文本
        if self.register(base) || self.mem.contains_key(base) {
            Some(self.mem.get(base)?)
        } else {
            None
        }
    }

    fn stack_of_mut(&mut self, base: &str) -> &mut HashMap<i64, Val> {
        self.mem.entry(base.to_string()).or_default()
    }

    /// address_base：地址 → (基文本, 偏移)。
    pub fn address_base(&self, address: &Lambda) -> (String, i64) {
        if address.deref_count > 0 || address.is_operation() {
            return (render_base_key(address), 0);
        }
        match &address.obj {
            Obj::Reg(r) => (r.clone(), address.imm),
            Obj::None => (render_base_key(address), 0),
            _ => (render_base_key(address), 0),
        }
    }

    /// resolve_address。
    pub fn resolve_address(&self, address: &Lambda) -> (Option<String>, i64) {
        let (base, offset) = self.address_base(address);
        let stack = if self.register(&base) || self.mem.contains_key(&base) {
            Some(base)
        } else {
            None
        };
        (stack, offset)
    }

    /// track_write（values 逐字写入；sp 纯栈写免 writable）。
    pub fn track_write(&mut self, dst_l: Lambda, values: Vec<Val>) {
        let (base_key, offset) = {
            let (b, o) = self.address_base(&dst_l);
            (b, o)
        };
        if dst_l.is_operation() {
            // 操作地址：记入 derived_writes
            self.derived_writes.push((dst_l.clone(), values.clone()));
        }
        let size = self.size_t();
        // 解析目标栈（base 是寄存器名 → 已跟踪）
        if self.register(&base_key) {
            let stack = self.stack_of_mut(&base_key);
            for (i, v) in values.iter().enumerate() {
                stack.insert(offset + size * i as i64, v.clone());
            }
        }
        // writable（sp 自身免）
        if base_key != self.sp {
            self.add_writable(dst_l);
        }
    }

    /// stored_value：候选写过该槽则返回其值。
    pub fn stored_value(&self, val: &Val) -> Option<Val> {
        let Val::Lambda(l) = val else { return None };
        if l.deref_count == 0 {
            return None;
        }
        let Ok(peeled) = l.clone().ref_() else { return None };
        let (Some(base), offset) = self.resolve_address(&peeled) else { return None };
        self.stack_of(&base)?.get(&offset).cloned()
    }

    /// read_value：写过→读回；否则记 deferred read。
    pub fn read_value(&mut self, val: Val) -> Val {
        if let Some(stored) = self.stored_value(&val) {
            return stored;
        }
        self.note_read(&val);
        val
    }

    /// note_read：不可控基的解引用 → deferred readable。
    pub fn note_read(&mut self, val: &Val) {
        let Val::Lambda(l) = val else { return };
        if l.deref_count == 0 {
            return;
        }
        let Ok(ptr) = l.clone().ref_() else { return };
        let root = ptr.root_name().map(|s| s.to_string());
        if let Some(r) = root {
            if self.mapped_pointer(&r) {
                return;
            }
        }
        self.deferred_reads.push((Val::Lambda(ptr), false));
    }

    /// writes_through。
    pub fn writes_through(&self, text: &str) -> Vec<String> {
        if text.is_empty() {
            return vec![];
        }
        let mut out = Vec::new();
        for (base, values) in &self.derived_writes {
            if operands_of(&Val::Lambda(base.clone()))
                .iter()
                .any(|op| op == text)
            {
                for v in values {
                    if !matches!(v, Val::Int(_)) {
                        let s = v.to_string();
                        if !out.contains(&s) {
                            out.push(s);
                        }
                    }
                }
            }
        }
        out
    }
}

/// address_base 的基键：整个表达式文本（非 plain base+offset 情形）。
fn render_base_key(l: &Lambda) -> String {
    // obj+op 渲染（不含 imm）——与 Ruby base.to_s 一致性足够（键用途）
    l.to_string()
}

fn operands_of(v: &Val) -> Vec<String> {
    match v {
        Val::Lambda(l) if l.is_operation() => {
            let mut out = operands_of(&l.obj.clone().into_lambda_val());
            if let Some((_, rhs)) = &l.op {
                match &**rhs {
                    Val::Lambda(_) => out.extend(operands_of(rhs)),
                    other => out.push(other.to_string()),
                }
            }
            out
        }
        other => vec![other.to_string()],
    }
}

impl Obj {
    fn into_lambda_val(self) -> Val {
        match self {
            Obj::Nested(v) => *v,
            Obj::Reg(r) => Val::Lambda(Lambda::reg(&r)),
            Obj::Base => Val::Lambda(Lambda::libc_base()),
            Obj::None => Val::Int(0),
        }
    }
}

// ================= DataProcessing =================

impl State {
    /// arith（+/-）：offset 结果优先；sp 不得变基。
    pub fn arith(&mut self, plus: bool, dst: &str, src: &str, op2: &str) -> EmuResult<()> {
        self.check_register(dst)?;
        let (src, op2) = shorthand(dst, src, op2);
        let lhs = self.value_of(src)?;
        let rhs = self.value_of(op2)?;
        let result = offset_result(plus, &lhs, &rhs)
            .or_else(|| {
                if dst == self.sp {
                    None
                } else {
                    operation_result(if plus { "+" } else { "-" }, &lhs, &rhs)
                }
            })
            .ok_or_else(|| State::err_unsupported_pub(if plus { "+" } else { "-" }, &[dst, src, op2]))?;
        self.registers.set(dst, result);
        Ok(())
    }

    /// data_op：and/orr/eor/lsl/lsr。
    pub fn data_op(&mut self, op: char, dst: &str, src: &str, op2: &str, name: &str) -> EmuResult<()> {
        self.check_register(dst)?;
        let (src, op2) = shorthand(dst, src, op2);
        let result = operation_result_char(op, &self.value_of(src)?, &self.value_of(op2)?)
            .ok_or_else(|| State::err_unsupported_pub(name, &[dst, src, op2]))?;
        let masked = match result {
            Val::Int(i) => Val::Int((i as u64 & self.width_mask()) as i64),
            other => other,
        };
        self.registers.set(dst, masked);
        Ok(())
    }

    /// complement（bic/mvn）。
    pub fn complement(&self, name: &str, op2: &str, reported: &[&str]) -> EmuResult<i64> {
        let v = self.value_of(op2)?;
        let Val::Int(i) = v else {
            return Err(State::err_unsupported_pub(name, reported));
        };
        Ok(!i & self.width_mask() as i64)
    }

    /// resolve_int_regs：把持有整数的寄存器 token 替换为整数文本。
    pub fn resolve_int_regs(&self, s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c.is_ascii_alphabetic() {
                let mut tok = String::new();
                tok.push(c);
                while let Some(&n) = chars.peek() {
                    if n.is_ascii_alphanumeric() || n == '_' {
                        tok.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if self.register(&tok) {
                    if let Val::Int(v) = self.registers.get(&tok) {
                        out.push_str(&hex(v));
                        continue;
                    }
                }
                out.push_str(&tok);
            } else {
                out.push(c);
            }
        }
        out
    }
}

/// shorthand（2-operand → 3-operand）。
pub fn shorthand<'a>(dst: &'a str, src: &'a str, op2: &'a str) -> (&'a str, &'a str) {
    if op2.is_empty() {
        (dst, src)
    } else {
        (src, op2)
    }
}

/// offset_result：rhs 为整数 → 直接折叠；加法 lhs 整数交换。
fn offset_result(plus: bool, lhs: &Val, rhs: &Val) -> Option<Val> {
    // rhs 为整数 → 直接折叠
    if let Val::Int(r) = rhs {
        return match lhs {
            Val::Int(l) => Some(Val::Int(if plus { l + r } else { l - r })),
            Val::Lambda(l) => Some(Val::Lambda(if plus { l.clone().add(*r) } else { l.clone().add(-*r) })),
            _ => None,
        };
    }
    // 加法的 lhs 为整数 → 交换后折叠（Ruby offset_result 原语义；
    // arm 的 `ldr r0, [pc]; add r0, pc` = Int + $base 走此路径）
    if plus {
        if let (Val::Int(l), Val::Lambda(r)) = (lhs, rhs) {
            return Some(Val::Lambda(r.clone().add(*l)));
        }
    }
    None
}

/// operation_result（字符串 op 形式）。
fn operation_result(op: &str, lhs: &Val, rhs: &Val) -> Option<Val> {
    operation_result_char(op.chars().next()?, lhs, rhs)
}

/// operation_result：折叠或命名为运算。
fn operation_result_char(op: char, lhs: &Val, rhs: &Val) -> Option<Val> {
    if let (Val::Int(l), Val::Int(r)) = (lhs, rhs) {
        // i64 折叠（移位/溢出由调用方 mask）
        let v = match op {
            '+' => l.checked_add(*r)?,
            '-' => l.checked_sub(*r)?,
            '&' => l & r,
            '|' => l | r,
            '^' => l ^ r,
            // lsl/lsr：Ruby 整数任意精度，u64 足够寄存器宽度
            '<' => {
                if *r < 0 || *r >= 64 { return None; }
                ((*l as u64) << (*r as u32)) as i64
            }
            '>' => {
                if *r < 0 || *r >= 64 { return None; }
                ((*l as u64) >> (*r as u32)) as i64
            }
            _ => return None,
        };
        return Some(Val::Int(v));
    }
    let Val::Lambda(l) = lhs else { return None };
    // xor 自身 = 0
    if op == '^' && lhs == rhs {
        return Some(Val::Int(0));
    }
    let op_str = match op {
        '+' => "+",
        '-' => "-",
        '&' => "&",
        '|' => "|",
        '^' => "^",
        '<' => "<<", // lsl
        '>' => ">>", // lsr
        _ => return None,
    };
    Some(Val::Lambda(Lambda::operation(l.clone(), op_str, rhs.clone())))
}

// ================= Constraints（输出） =================

impl State {
    /// finalize_deferred_reads + 输出约束列表（master Constraints#constraints）。
    pub fn constraints(&mut self) -> Vec<String> {
        self.finalize_deferred_reads();
        if self.constraints.is_empty() {
            return vec![];
        }
        // 排序（地址约束 deref0 按 imm 升序在前）+ 按 (type, base) 去重取最小 offset
        let mut cons: Vec<CtItem> = self.constraints.clone();
        cons.sort_by(|a, b| ct_sort_key(a).cmp(&ct_sort_key(b)));
        cons.dedup_by(|a, b| ct_key(a) == ct_key(b));
        let cons = self.drop_implied_nonzero(cons);
        let cons = self.drop_restated_null(cons);
        let mut out: Vec<String> = cons.iter().map(render_ct).collect();
        out.sort();
        out
    }

    fn finalize_deferred_reads(&mut self) {
        let deferred = std::mem::take(&mut self.deferred_reads);
        for (arg, nullable) in deferred {
            let Val::Lambda(l) = &arg else { continue };
            if nullable {
                if self.deref_safe_pointer(l) || self.writable_pointer(l) {
                    continue;
                }
                self.constraints.push(CtItem::Raw(format!("{arg} == NULL")));
            } else {
                if self.mapped_nonnull_pointer_pub(l) || self.writable_pointer(l) {
                    continue;
                }
                self.constraints.push(CtItem::Readable(l.clone()));
            }
        }
    }

    fn deref_safe_pointer(&self, l: &Lambda) -> bool {
        l.deref_count == 0 && self.mapped_pointer(&l.obj_str())
    }

    fn writable_pointer(&self, l: &Lambda) -> bool {
        if l.deref_count != 0 {
            return false;
        }
        let base = l.obj_str();
        if self.constraints.iter().any(|c| matches!(c, CtItem::Writable(w) if w.obj_str() == base)) {
            return true;
        }
        // tracked memory 非空
        if let Some(stack) = self.stack_of(&base) {
            if !stack.is_empty() {
                return true;
            }
        }
        false
    }

    fn mapped_nonnull_pointer_pub(&self, l: &Lambda) -> bool {
        l.deref_count == 0 && self.mapped_pointer(&l.obj_str())
    }

    #[allow(dead_code)] // arm/riscv/mips 切片接入后使用
    pub fn closed_fds(&self) -> Vec<String> {
        let mut out = self.closed_fds.clone();
        out.dedup();
        out
    }
}

fn ct_sort_key(c: &CtItem) -> (u8, i64, String) {
    match c {
        CtItem::Writable(l) if l.deref_count == 0 => (0, l.imm, String::new()),
        CtItem::Readable(l) if l.deref_count == 0 => (0, l.imm, String::new()),
        CtItem::Writable(l) => (1, 0, l.to_string()),
        CtItem::Readable(l) => (1, 0, l.to_string()),
        CtItem::Cmp(l, _, _) => (2, 0, l.clone()),
        CtItem::Raw(s) => (3, 0, s.clone()),
    }
}

fn ct_key(c: &CtItem) -> (u8, String) {
    match c {
        CtItem::Writable(l) | CtItem::Readable(l) => {
            let kind = if matches!(c, CtItem::Writable(_)) { 0 } else { 1 };
            let key = if l.deref_count == 0 { l.obj_str() } else { l.to_string() };
            (kind, key)
        }
        CtItem::Cmp(_, _, _) => (2, render_ct(c)),
        CtItem::Raw(s) => (3, s.clone()),
    }
}

fn render_ct(c: &CtItem) -> String {
    match c {
        CtItem::Writable(l) => format!("writable: {l}"),
        CtItem::Readable(l) => format!("readable: {l}"),
        CtItem::Cmp(l, o, r) => format!("{l} {o} {r}"),
        CtItem::Raw(s) => s.clone(),
    }
}

impl State {
    fn drop_implied_nonzero(&self, cons: Vec<CtItem>) -> Vec<CtItem> {
        let nonzero_regs: Vec<String> = cons
            .iter()
            .filter_map(|c| match c {
                CtItem::Writable(l) | CtItem::Readable(l) if l.deref_count == 0 => {
                    Some(l.obj_str())
                }
                _ => None,
            })
            .collect();
        if nonzero_regs.is_empty() {
            return cons;
        }
        cons.into_iter()
            .filter(|c| match c {
                CtItem::Cmp(l, o, r) => {
                    !(o == "!=" && r == ZERO && nonzero_regs.contains(l))
                }
                _ => true,
            })
            .collect()
    }

    fn drop_restated_null(&self, cons: Vec<CtItem>) -> Vec<CtItem> {
        let nulls: Vec<String> = cons
            .iter()
            .filter_map(|c| match c {
                CtItem::Raw(s) => s.strip_suffix(" == NULL").map(|x| x.to_string()),
                _ => None,
            })
            .collect();
        if nulls.is_empty() {
            return cons;
        }
        cons.into_iter()
            .filter(|c| match c {
                CtItem::Cmp(l, o, r) => !(o == "==" && r == ZERO && nulls.contains(l)),
                _ => true,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::AbiArch;

    #[test]
    fn test_relation() {
        assert_eq!(relation("eq"), Some(("==", None)));
        assert_eq!(relation("uge"), Some((">=", Some(false))));
        assert_eq!(relation("sle"), Some(("<=", Some(true))));
        assert_eq!(relation("vs"), None);
    }

    #[test]
    fn test_satisfiable() {
        let t = |l: &str, o: &str, r: &str| (l.to_string(), o.to_string(), r.to_string());
        assert!(satisfiable(&[t("x", "==", "0x1")]));
        assert!(!satisfiable(&[t("x", "==", "0x0"), t("x", "!=", "0x0")]));
        assert!(!satisfiable(&[t("x", ">", "0x5"), t("x", "<", "0x5")]));
        assert!(satisfiable(&[t("x", ">=", "0x5"), t("x", "<=", "0x5")]));
        // 非整数 rhs 忽略
        assert!(satisfiable(&[t("x", "==", "rsp")]));
    }

    #[test]
    fn test_compare_triple_sub() {
        // b.ne not-taken after cmp x2, 1 → x2 == 0x1
        let r = compare_triple(CmpOp::Sub, "x2".into(), "0x1".into(), "!=", None, false, 64);
        assert_eq!(r, ("x2".to_string(), "==".to_string(), "0x1".to_string()));
        let r = compare_triple(CmpOp::Sub, "x2".to_string(), "0x1".into(), "!=", None, true, 64);
        assert_eq!(r, ("x2".to_string(), "!=".to_string(), "0x1".to_string()));
    }

    #[test]
    fn test_compare_triple_add_carry() {
        // cmn x0, 0x1000 + b.le(u) → x0 <= 0xfffffffffffff000
        let r = compare_triple(
            CmpOp::Add,
            "x0".into(),
            "0x1000".into(),
            "<=",
            Some(false),
            true,
            64,
        );
        assert_eq!(r.2, "0xfffffffffffff000".to_string());
        // 等式条件保留和形式
        let r = compare_triple(CmpOp::Add, "x0".into(), "0x1000".into(), "!=", None, true, 64);
        assert_eq!(r.0, "(x0 + 0x1000)".to_string());
    }

    #[test]
    fn test_track_write_read_back() {
        let mut st = State::new(AbiArch::Aarch64, "sp", "pc", Some("x29"));
        let dst = Lambda::reg("sp").add(0x10);
        st.track_write(dst, vec![Val::Lambda(Lambda::reg("x19"))]);
        let v = st.stored_value(&Val::Lambda(Lambda::reg("sp").add(0x10).deref()));
        assert_eq!(v.map(|x| x.to_string()), Some("x19".to_string()));
    }

    #[test]
    fn test_constraints_dedup() {
        let mut st = State::new(AbiArch::Aarch64, "sp", "pc", None);
        st.add_writable(Lambda::reg("x19").add(0x40));
        st.add_writable(Lambda::reg("x19").add(0x48)); // 同 base 更大 offset：被去重
        let cons = st.constraints();
        assert_eq!(cons, vec!["writable: x19+0x40".to_string()]);
    }

    #[test]
    fn test_drop_implied_nonzero() {
        let mut st = State::new(AbiArch::Aarch64, "sp", "pc", None);
        st.constraints.push(CtItem::Writable(Lambda::reg("x19").add(0x40)));
        st.constraints.push(CtItem::Cmp("x19".into(), "!=".into(), ZERO.into()));
        let cons = st.constraints();
        assert_eq!(cons, vec!["writable: x19+0x40".to_string()]);
    }
}
