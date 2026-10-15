//! 2.1.1 管线的符号值表示（对齐 master `emulators/lambda.rb` + `register_file.rb`）。
//!
//! 与 1.10.0 管线（`crate::lambda`）的差异：
//! - `Val::Int(i64)`：Ruby Integer 对应（渲染十进制）
//! - 操作（`(a & b)`）：`op` 为字符串 + rhs 为任意 `Val`（x86 只有 `(a & imm)`）
//! - 寄存器文件：窄名视图（w0→x0、edi→rdi）共享存储
//!
//! 渲染与 Ruby 逐字对齐：`[rsp+0x50]`、`$base+0x1d8698`、`(rdi & 0xf)`、
//! `((a5 << 0x3) + [sp+0xd0])`。

use std::collections::HashMap;
use std::fmt;

pub mod processor;
pub mod mixins;
pub mod aarch64;
pub mod arm;
pub mod riscv64;

/// 一个符号值：整数、寄存器表达式、call 目标字符串或「被 call 破坏」哨兵。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Val {
    Int(i64),
    Lambda(Lambda),
    /// call 目标（存进 pc 寄存器；resolve 读它决定 effect）。
    Str(String),
    Clobbered,
}

/// 符号表达式：`base (+ imm)? (deref)*`，外加可选二元运算。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lambda {
    pub obj: Obj,
    pub imm: i64,
    pub deref_count: u32,
    /// 运算：`(obj op rhs)`。obj 只作为 lhs 参与渲染。
    pub op: Option<(String, Box<Val>)>,
}

/// 表达式的基：寄存器 / `$base` / 嵌套值。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Obj {
    Reg(String),
    Base, // $base
    Nested(Box<Val>),
    /// based-nowhere（`[0x1234]` 绝对地址）。
    None,
}

impl Lambda {
    pub fn reg(name: &str) -> Self {
        Lambda { obj: Obj::Reg(name.into()), imm: 0, deref_count: 0, op: None }
    }

    pub fn libc_base() -> Self {
        Lambda { obj: Obj::Base, imm: 0, deref_count: 0, op: None }
    }

    pub fn nested(inner: Val) -> Self {
        Lambda { obj: Obj::Nested(Box::new(inner)), imm: 0, deref_count: 0, op: None }
    }

    /// `self + imm`：deref>0 时嵌套（Ruby `Lambda#+`）。
    pub fn add(self, imm: i64) -> Self {
        if self.deref_count > 0 {
            let mut ret = Lambda::nested(Val::Lambda(self));
            ret.imm = imm;
            ret
        } else {
            let mut r = self;
            r.imm += imm;
            r
        }
    }

    pub fn deref(self) -> Self {
        let mut r = self;
        r.deref_count += 1;
        r
    }

    pub fn ref_(self) -> Result<Self, String> {
        if self.deref_count == 0 {
            return Err("Cannot reference anymore!".into());
        }
        let mut r = self;
        r.deref_count -= 1;
        Ok(r)
    }

    /// `Lambda.operation(lhs, op, rhs)`：`(lhs op rhs)` 形式的值。
    pub fn operation(lhs: impl Into<Val>, op: &str, rhs: impl Into<Val>) -> Self {
        Lambda {
            obj: Obj::Nested(Box::new(lhs.into())),
            imm: 0,
            deref_count: 0,
            op: Some((op.to_string(), Box::new(rhs.into()))),
        }
    }

    pub fn is_operation(&self) -> bool {
        self.op.is_some()
    }

    /// 根基（Ruby root_base）：沿 Nested 下钻到 Reg/Base；Int 返回 None。
    pub fn root_obj(&self) -> Option<&Obj> {
        match &self.obj {
            Obj::Nested(b) => match &**b {
                Val::Lambda(l) => l.root_obj(),
                _ => None,
            },
            o => Some(o),
        }
    }

    pub fn root_name(&self) -> Option<&str> {
        match self.root_obj() {
            Some(Obj::Reg(r)) => Some(r),
            // master root_base 返回 obj 本身：$base 是真实根（mapped），None 是绝对地址
            Some(Obj::Base) => Some("$base"),
            _ => None,
        }
    }

    /// Ruby `obj.to_s`：仅基文本（不含 imm/deref）。
    pub fn obj_str(&self) -> String {
        match &self.obj {
            Obj::Reg(r) => r.clone(),
            Obj::Base => "$base".into(),
            Obj::Nested(v) => v.to_string(),
            Obj::None => String::new(),
        }
    }
}

impl From<i64> for Val {
    fn from(v: i64) -> Self {
        Val::Int(v)
    }
}

impl From<Lambda> for Val {
    fn from(l: Lambda) -> Self {
        Val::Lambda(l)
    }
}

impl Val {
    /// 值文本（约束/effect 渲染用）。Ruby：Integer#to_s 十进制；Lambda#to_s。
    #[allow(dead_code)] // arm/riscv/mips 切片接入后使用
    pub fn is_int(&self) -> bool {
        matches!(self, Val::Int(_))
    }

    #[allow(dead_code)]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Val::Int(v) => Some(*v),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_lambda(&self) -> Option<&Lambda> {
        match self {
            Val::Lambda(l) => Some(l),
            _ => None,
        }
    }
}

impl fmt::Display for Lambda {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let opens = "[".repeat(self.deref_count as usize);
        let closes = "]".repeat(self.deref_count as usize);
        write!(f, "{opens}{}{}{closes}", self.base_str(), self.imm_str())
    }
}

impl Lambda {
    fn imm_str(&self) -> String {
        if self.imm == 0 {
            String::new()
        } else if self.imm > 0 {
            format!("+0x{:x}", self.imm)
        } else {
            format!("-0x{:x}", -self.imm)
        }
    }

    fn base_str(&self) -> String {
        let core = match &self.obj {
            Obj::Reg(r) => r.clone(),
            Obj::Base => "$base".to_string(),
            Obj::Nested(v) => v.to_string(),
            Obj::None => String::new(),
        };
        match &self.op {
            None => core,
            Some((op, rhs)) => {
                let rhs_str = match &**rhs {
                    // Ruby: rhs Integer → Helper.hex
                    Val::Int(v) => crate::lambda::hex(*v),
                    other => other.to_string(),
                };
                format!("({core} {op} {rhs_str})")
            }
        }
    }
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Ruby Integer#to_s：十进制
            Val::Int(v) => write!(f, "{v}"),
            Val::Lambda(l) => write!(f, "{l}"),
            Val::Str(s) => write!(f, "{s}"),
            Val::Clobbered => write!(f, "$clobbered"),
        }
    }
}

/// `Lambda.parse(argument, predefined:)`（2.1.1 语义）。
///
/// - 空/`!` → Int(0)
/// - 整数 → Int
/// - `[...]`（最后一个 `]`）→ 内层 deref + 尾随 imm
/// - `reg±imm`：predefined 命中先替换再折叠；**值为 String（call 目标）时当新基**
/// - obj 为 Int 时（`[0x1234]`）→ based-nowhere（Nested(Int)）
pub fn parse_val(arg: &str, predefined: &HashMap<String, Val>) -> Result<Val, ()> {
    let arg = arg.trim();
    if arg.is_empty() || arg == "!" {
        return Ok(Val::Int(0));
    }
    if let Some(v) = crate::lambda::parse_int_str(arg) {
        return Ok(Val::Int(v));
    }
    if arg.starts_with('[') {
        let Some(ridx) = arg.rfind(']') else { return Err(()) };
        let inner = &arg[1..ridx];
        let tail = &arg[ridx + 1..];
        let imm = if tail.is_empty() || tail == "!" {
            0
        } else {
            crate::lambda::parse_int_str(tail).ok_or(())?
        };
        let inner_val = match parse_val(inner, predefined)? {
            Val::Int(i) => Val::Lambda(Lambda { obj: Obj::None, imm: i, deref_count: 0, op: None }), // based-nowhere
            other => other,
        };
        let Val::Lambda(mut l) = inner_val else { return Err(()) };
        l = l.deref();
        if imm != 0 {
            l = l.add(imm);
        }
        return Ok(Val::Lambda(l));
    }
    let (base, disp) = mem_obj(arg)?;
    let obj_val = match predefined.get(base.as_str()) {
        Some(Val::Lambda(l)) => Val::Lambda(l.clone()),
        Some(Val::Int(i)) => Val::Int(*i),
        // 未定义或 Str（call 目标，call 后 pc 寄存器）：当新基
        _ => Val::Lambda(Lambda::reg(&base)),
    };
    Ok(match obj_val {
        Val::Int(c) => Val::Int(c + disp),
        Val::Lambda(mut l) => {
            if disp != 0 {
                l = l.add(disp);
            }
            Val::Lambda(l)
        }
        _ => return Err(()),
    })
}

/// `reg` / `reg±imm` / `reg, imm` 拆分（Ruby mem_obj 的 token 化语义）。
fn mem_obj(arg: &str) -> Result<(String, i64), ()> {
    // Ruby：gsub(/[+-]/, ' \0') 在符号前断词，再 scan(/[+\-\w]+/)
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev_sign = false;
    for c in arg.chars() {
        if c == '+' || c == '-' {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            cur.push(c);
            prev_sign = true;
        } else if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
            prev_sign = false;
        } else if !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
            prev_sign = false;
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    let _ = prev_sign;
    match tokens.as_slice() {
        [t] => Ok((t.clone(), 0)),
        [base, disp] => {
            let d = crate::lambda::parse_int_str(disp).ok_or(())?;
            Ok((base.clone(), d))
        }
        _ => Err(()),
    }
}

/// Ruby `Helper.hex`：`0x10` / `-0x10`。
pub fn hex(v: i64) -> String {
    if v >= 0 {
        format!("0x{v:x}")
    } else {
        format!("-0x{:x}", -v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_render() {
        assert_eq!(Lambda::reg("rsp").add(0x50).deref().to_string(), "[rsp+0x50]");
        assert_eq!(Lambda::libc_base().add(0x1d8698).to_string(), "$base+0x1d8698");
        assert_eq!(Lambda::reg("rax").deref().add(8).to_string(), "[rax]+0x8");
    }

    #[test]
    fn test_operation() {
        let l = Lambda::operation(Lambda::reg("rdi"), "&", Val::Int(0xf));
        assert_eq!(l.to_string(), "(rdi & 0xf)");
        let nested = Lambda::operation(l.clone(), "+", Lambda::reg("sp").add(0xd0).deref());
        assert_eq!(nested.to_string(), "((rdi & 0xf) + [sp+0xd0])");
    }

    #[test]
    fn test_parse() {
        let e = HashMap::new();
        assert_eq!(parse_val("0x30", &e).unwrap(), Val::Int(0x30));
        assert_eq!(parse_val("[rsp+0x70]", &e).unwrap().to_string(), "[rsp+0x70]");
        assert_eq!(parse_val("[sp, 4]", &e).unwrap().to_string(), "[sp+0x4]");
        assert_eq!(parse_val("sp, -4", &e).unwrap().to_string(), "sp-0x4");
    }

    #[test]
    fn test_parse_based_nowhere() {
        let e = HashMap::new();
        assert_eq!(parse_val("[0x1234]", &e).unwrap().to_string(), "[+0x1234]");
    }

    #[test]
    fn test_predefined_string_target() {
        // call 后 pc 寄存器值为 String（call 目标）：当新基
        let e: HashMap<String, Val> = HashMap::new();
        let v = parse_val("pc", &e).unwrap();
        assert_eq!(v.to_string(), "pc");
    }

    #[test]
    fn test_root() {
        let l = Lambda::reg("x19").add(0xed8);
        assert_eq!(l.root_name(), Some("x19"));
        let n = Lambda::nested(Val::Lambda(Lambda::libc_base().add(0x10).deref()))
            .add(8)
            .deref();
        // master root_base 对 Obj::Base 返回自身 → root_name 为 "$base"
        assert_eq!(n.root_name(), Some("$base"));
        assert_eq!(n.to_string(), "[[$base+0x10]+0x8]");
    }

    #[test]
    fn test_int_render_decimal() {
        assert_eq!(Val::Int(0).to_string(), "0");
        assert_eq!(Val::Int(-1).to_string(), "-1");
        assert_eq!(hex(0x10), "0x10");
        assert_eq!(hex(-0x10), "-0x10");
    }

    #[test]
    fn test_ref() {
        let l = Lambda::reg("rsp").add(0x50).deref();
        assert_eq!(l.clone().ref_().unwrap().to_string(), "rsp+0x50");
        assert!(Lambda::reg("rax").ref_().is_err());
    }
}
