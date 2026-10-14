//! 符号值：rog 符号执行的核心表示。
//!
//! 对齐 one_gadget 的 `Lambda`：一个值是「基（寄存器名 / libc 基址 / 嵌套值）
//! + 常量偏移 + 解引用次数 + 可选运算（如 `& mask`）」。
//! 渲染文本与 one_gadget 逐字对齐（`[rsp+0x50]`、`$base+0x1d8698`、`(rdi & 0xf)` …）。

use std::fmt;
use std::sync::Arc;

/// 值的基：一个寄存器名、libc 装载基址（`$base`）、或嵌套的另一个值。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Base {
    /// 寄存器名，如 `rax`、`rsp`。
    Reg(Arc<str>),
    /// libc 装载基址；`imm` 是文件偏移（concretized rip-relative 结果）。
    /// 当前流水线 rip 保持符号（1.10.0 语义），此基仅测试用。
    #[allow(dead_code)]
    LibcBase,
    /// 嵌套值：`[[rbp-0x8]+0x4]` 的内层。
    Nested(Box<Val>),
}

/// 符号表达式：`base (+ imm)? (deref)*`，外加可选的一元运算包装。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lambda {
    pub base: Base,
    pub imm: i64,
    pub deref_count: u32,
    /// 可选运算（`&`、`>>` 等），`op rhs` 应用在整个 base+imm 上。
    pub op: Option<(char, i64)>,
}

/// 一个被模拟的值：常量、符号表达式、XMM 向量（按 64-bit lane 拆两半）或「被 call 破坏」。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Val {
    /// 具体整数（可负：movsxd / sub 的结果）。
    Const(i64),
    Lambda(Lambda),
    /// 128-bit XMM：两 lane（amd64 上 movq/movhps/punpcklqdq 的语义）。
    Xmm(Vec<Box<Val>>),
    /// caller-saved 寄存器被安全调用破坏后的值（1.10.0 语义哨兵，
    /// 当前安全调用集合不 clobber，保持枚举完备性）。
    #[allow(dead_code)]
    Clobbered,
}

impl Lambda {
    pub fn reg(name: &str) -> Self {
        Lambda {
            base: Base::Reg(name.into()),
            imm: 0,
            deref_count: 0,
            op: None,
        }
    }

    /// `self + imm`（保留 deref：`[x+1]+2` 是新 lambda 套旧）。
    pub fn add_imm(self, imm: i64) -> Self {
        if self.deref_count > 0 {
            // 套一层：ret = Lambda(self) + imm
            let inner = self;
            Lambda {
                base: Base::Nested(Box::new(Val::Lambda(inner))),
                imm,
                deref_count: 0,
                op: None,
            }
        } else {
            let mut r = self;
            r.imm += imm;
            r
        }
    }

    /// deref + 1（生成新对象）。
    pub fn deref(self) -> Self {
        let mut r = self;
        r.deref_count += 1;
        r
    }

    /// libc 装载基址 lambda（渲染测试用）。
    #[cfg(test)]
    pub fn libc_base() -> Self {
        Lambda { base: Base::LibcBase, imm: 0, deref_count: 0, op: None }
    }

    /// 嵌套基构造（渲染/求根名测试用）。
    #[cfg(test)]
    pub fn nested(inner: Val) -> Self {
        Lambda { base: Base::Nested(Box::new(inner)), imm: 0, deref_count: 0, op: None }
    }

    /// deref - 1；已经是 0 则报错。
    pub fn ref_(self) -> Result<Self, String> {
        if self.deref_count == 0 {
            return Err("Cannot reference anymore!".into());
        }
        let mut r = self;
        r.deref_count -= 1;
        Ok(r)
    }

    /// 是否是「裸寄存器」：无 deref、无 imm、无 op。
    #[allow(dead_code)] // 测试与未来调用保留
    pub fn is_bare_reg(&self) -> bool {
        self.deref_count == 0 && self.imm == 0 && self.op.is_none() && matches!(self.base, Base::Reg(_))
    }

    /// 根基名（沿 Nested 链下钻）。
    pub fn root_name(&self) -> Option<&str> {
        match &self.base {
            Base::Reg(r) => Some(r),
            Base::LibcBase => None,
            Base::Nested(v) => match &**v {
                Val::Lambda(l) => l.root_name(),
                _ => None,
            },
        }
    }

    /// 根基名（String 版本，便于临时构造的字符串基名）。
    pub fn root_name_str(&self) -> Option<&str> {
        self.root_name()
    }

    /// Ruby `Lambda#obj.to_s`：仅基对象文本（不含 imm/deref）。
    /// i386 resolve 的 base_reg 提取用（`arg0.deref.obj.to_s`）。
    pub fn obj_str(&self) -> String {
        self.base_str()
    }
}

/// 1.10.0 `Lambda.parse(argument, predefined:)` 的 Rust 对应。
///
/// 关键语义：
/// - 空串/`!` → 0
/// - 纯整数 → Const
/// - `[expr]`（最后一个 `]` 收口）→ 内层 parse 后 deref，尾随 imm 相加
/// - `reg+imm` / `reg-imm`：reg 是 predefined 键时**先替换再折叠 imm**
///   （`[r8+0x10]` 且 r8=rbp-0x50 → `[rbp-0x40]`，不产生嵌套）
pub fn parse_operand(arg: &str, predefined: &std::collections::HashMap<String, Val>) -> Result<Val, ()> {
    let arg = arg.trim();
    if arg.is_empty() || arg == "!" {
        return Ok(Val::Const(0));
    }
    if let Some(v) = crate::lambda::parse_int_str(arg) {
        return Ok(Val::Const(v));
    }
    // 嵌套 []：最外层 [ ... ] + 尾随 imm
    if arg.starts_with('[') {
        let Some(ridx) = arg.rfind(']') else { return Err(()) };
        let inner = &arg[1..ridx];
        let tail = &arg[ridx + 1..];
        let imm = if tail.is_empty() { 0 } else { parse_int_str(tail).ok_or(())? };
        let Val::Lambda(mut l) = parse_operand(inner, predefined)? else { return Err(()) };
        l = l.deref();
        if imm != 0 {
            l = l.add_imm(imm);
        }
        return Ok(Val::Lambda(l));
    }
    // reg / reg±imm
    let (base, disp) = mem_obj(arg)?;
    let obj_val = match predefined.get(base) {
        Some(v) => v.clone(),
        None => Val::Lambda(Lambda::reg(base)),
    };
    let out = match obj_val {
        Val::Const(c) => Val::Const(c + disp),
        Val::Lambda(l) => {
            let mut l = l;
            if disp != 0 {
                l = l.add_imm(disp);
            }
            Val::Lambda(l)
        }
        _ => return Err(()),
    };
    Ok(out)
}

/// `reg` / `reg+imm` / `reg-imm` 拆分（mem_obj）。
fn mem_obj(arg: &str) -> Result<(&str, i64), ()> {
    // 找 +/- 分割（第一个）
    if let Some(pos) = arg.find(['+', '-']) {
        let base = &arg[..pos];
        let rest = &arg[pos..];
        let disp = parse_int_str(rest).ok_or(())?;
        Ok((base, disp))
    } else {
        Ok((arg, 0))
    }
}

/// 整数解析（0x 前缀 / 十进制 / 负号）。
pub fn parse_int_str(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, body) = match s.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        // Ruby 整数任意精度：超 i64 的十六进制（如 0xfffffffffffffff0）按 u64 收
        i64::from_str_radix(h, 16)
            .ok()
            .or_else(|| u64::from_str_radix(h, 16).ok().map(|u| u as i64))?
    } else {
        body.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}

impl fmt::Display for Lambda {
    /// 与 one_gadget 渲染逐字对齐。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let opens = "[".repeat(self.deref_count as usize);
        let closes = "]".repeat(self.deref_count as usize);
        let imm_str = if self.immi_str().is_empty() {
            String::new()
        } else {
            self.immi_str()
        };
        write!(f, "{opens}{}{imm_str}{closes}", self.base_str())
    }
}

impl Lambda {
    fn immi_str(&self) -> String {
        if self.imm == 0 {
            String::new()
        } else if self.imm > 0 {
            format!("+0x{:x}", self.imm)
        } else {
            format!("-0x{:x}", -self.imm)
        }
    }

    fn base_str(&self) -> String {
        let core = match &self.base {
            Base::Reg(r) => r.to_string(),
            Base::LibcBase => "$base".to_string(),
            Base::Nested(v) => v.to_string(),
        };
        match &self.op {
            None => core,
            Some((op, rhs)) => format!("({core} {op} {rhs:#x})"),
        }
    }
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Ruby Integer#to_s：十进制、无前缀（effect 里 "0"、约束比较 =='0' 都靠它）
            Val::Const(c) => write!(f, "{c}"),
            Val::Lambda(l) => write!(f, "{l}"),
            // Ruby Array#to_s：全 lane、", " 连接（64 位 2 lane，32 位 4 lane）
            Val::Xmm(lanes) => write!(f, "[{}]", lanes.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")),
            // one_gadget 用 $clobbered；我们渲染为不可满足哨兵，resolver 会丢弃
            Val::Clobbered => write!(f, "$clobbered"),
        }
    }
}

/// one_gadget 的 `Helper.hex` 对齐（约束渲染用）。
pub fn hex(v: i64) -> String {
    if v >= 0 {
        format!("0x{v:x}")
    } else if let Some(p) = v.checked_neg() {
        format!("-0x{p:x}")
    } else {
        // i64::MIN：Ruby 任意精度下 -(-2**63) = 2**63 → 0x8000000000000000
        format!("-0x{:x}", (v as u128).wrapping_neg())
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse_operand_int() {
        let m = HashMap::new();
        assert_eq!(parse_operand("0x30", &m).unwrap(), Val::Const(0x30));
        assert_eq!(parse_operand("", &m).unwrap(), Val::Const(0));
        assert_eq!(parse_operand("!", &m).unwrap(), Val::Const(0));
    }

    #[test]
    fn test_parse_operand_reg() {
        let m = HashMap::new();
        let v = parse_operand("rsp+0x10", &m).unwrap();
        assert_eq!(v.to_string(), "rsp+0x10");
    }

    #[test]
    fn test_parse_operand_deref() {
        let m = HashMap::new();
        let v = parse_operand("[rsp+0x70]", &m).unwrap();
        assert_eq!(v.to_string(), "[rsp+0x70]");
    }

    #[test]
    fn test_parse_operand_predefined_folding() {
        // r8 = rbp-0x50；[r8+0x10] → [rbp-0x40]（imm 折叠，不嵌套）
        let mut m = HashMap::new();
        m.insert("r8".to_string(), Val::Lambda(Lambda::reg("rbp").add_imm(-0x50)));
        let v = parse_operand("[r8+0x10]", &m).unwrap();
        assert_eq!(v.to_string(), "[rbp-0x40]");
        // 再剥一层：[rax] 其中 rax=[rip+0x1c8569] → [[rip+0x1c8569]]
        let mut m2 = HashMap::new();
        m2.insert("rax".to_string(), Val::Lambda(Lambda::reg("rip").add_imm(0x1c8569).deref()));
        let v2 = parse_operand("[rax]", &m2).unwrap();
        assert_eq!(v2.to_string(), "[[rip+0x1c8569]]");
    }

    #[test]
    fn test_parse_operand_nested_tail_imm() {
        let m = HashMap::new();
        let v = parse_operand("[rsp+0x70]+0x8", &m).unwrap();
        assert_eq!(v.to_string(), "[rsp+0x70]+0x8");
    }

    #[test]
    fn test_parse_int_str() {
        assert_eq!(parse_int_str("0x10"), Some(0x10));
        assert_eq!(parse_int_str("-0x28"), Some(-0x28));
        assert_eq!(parse_int_str("42"), Some(42));
        assert_eq!(parse_int_str("rsp"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_basic() {
        let l = Lambda::reg("rsp").add_imm(0x50).deref();
        assert_eq!(l.to_string(), "[rsp+0x50]");
    }

    #[test]
    fn test_render_negative() {
        let l = Lambda::reg("rbp").add_imm(-0x48).deref();
        assert_eq!(l.to_string(), "[rbp-0x48]");
    }

    #[test]
     fn test_render_libc_base() {
        let l = Lambda::libc_base().add_imm(0x1d8698);
        assert_eq!(l.to_string(), "$base+0x1d8698");
    }

    #[test]
    fn test_render_nested() {
        let inner = Lambda::reg("rbp").add_imm(-0x48).deref();
        let outer = Lambda::nested(Val::Lambda(inner)).add_imm(0x8).deref();
        assert_eq!(outer.to_string(), "[[rbp-0x48]+0x8]");
    }

    #[test]
    fn test_ref() {
        let l = Lambda::reg("rsp").add_imm(0x50).deref();
        assert_eq!(l.clone().ref_().unwrap().to_string(), "rsp+0x50");
        assert!(l.ref_().is_ok());
        let bare = Lambda::reg("rax");
        assert!(bare.ref_().is_err());
    }

    #[test]
    fn test_add_imm_after_deref_nests() {
        let l = Lambda::reg("rax").deref().add_imm(8);
        assert_eq!(l.to_string(), "[rax]+0x8");
    }

    #[test]
    fn test_operation_render() {
        let l = Lambda {
            op: Some(('&', 0xf)),
            ..Lambda::reg("rdi")
        };
        assert_eq!(l.to_string(), "(rdi & 0xf)");
    }

    #[test]
    fn test_val_const_render() {
        // Ruby Integer#to_s：十进制（argv[1] == '0' 比较与 NULL 渲染依赖它）
        assert_eq!(Val::Const(1).to_string(), "1");
        assert_eq!(Val::Const(-1).to_string(), "-1");
        assert_eq!(Val::Const(0).to_string(), "0");
    }

    #[test]
    fn test_root_name() {
        let inner = Lambda::reg("rbp").add_imm(-0x48).deref();
        let outer = Lambda::nested(Val::Lambda(inner)).add_imm(0x8).deref();
        assert_eq!(outer.root_name(), Some("rbp"));
        assert_eq!(Lambda::libc_base().root_name(), None);
        assert_eq!(Lambda::reg("rax").root_name(), Some("rax"));
    }

    #[test]
    fn test_is_bare_reg() {
        assert!(Lambda::reg("rax").is_bare_reg());
        assert!(!Lambda::reg("rax").add_imm(8).is_bare_reg());
        assert!(!Lambda::reg("rax").deref().is_bare_reg());
    }
}
