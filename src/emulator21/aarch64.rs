//! aarch64 模拟器（master emulators/aarch64.rb + arm_family.rb 的 aarch64 部分）。

use super::processor::*;
use super::{hex, Val};
use crate::abi::AbiArch;

/// 支持指令表（aarch64.rb#instructions）。
pub(crate) const INSTRUCTIONS: &[(&str, usize, usize)] = &[
    ("add", 3, 4),
    ("adrp", 2, 2),
    ("and", 3, 3),
    ("bic", 3, 3),
    ("bl", 1, 1),
    ("bti", 0, 1),
    ("dmb", 0, 1),
    ("dsb", 0, 1),
    ("eor", 3, 3),
    ("isb", 0, 1),
    ("ldr", 2, 3),
    ("ldrb", 2, 3),
    ("lsl", 3, 3),
    ("lsr", 3, 3),
    ("mov", 2, 2),
    ("mvn", 2, 2),
    ("nop", 0, 1),
    ("orr", 3, 3),
    ("stp", 3, 3),
    ("str", 2, 3),
    ("sub", 3, 4),
];

/// arm_family COND：条件码 → RELATION 键。
pub(crate) fn cond_relation(cc: &str) -> Option<&'static str> {
    Some(match cc {
        "eq" => "eq",
        "ne" => "ne",
        "hs" | "cs" => "uge",
        "lo" | "cc" => "ult",
        "hi" => "ugt",
        "ls" => "ule",
        "ge" => "sge",
        "lt" => "slt",
        "gt" => "sgt",
        "le" => "sle",
        "mi" => "slt",
        "pl" => "sge",
        _ => return None, // vs/vc：无约束形式
    })
}

/// COMPARES：cmp→sub、cmn→add、tst→and。
fn compare_op(mnem: &str) -> Option<CmpOp> {
    match mnem {
        "cmp" => Some(CmpOp::Sub),
        "cmn" => Some(CmpOp::Add),
        "tst" => Some(CmpOp::And),
        _ => None,
    }
}

pub fn new_state() -> State {
    let mut st = State::new(AbiArch::Aarch64, "sp", "pc", Some("x29"));
    st.registers.set("xzr", Val::Int(0));
    st.registers.set("wzr", Val::Int(0));
    st
}

fn branch_mnem(mnem: &str) -> bool {
    mnem == "b" || mnem == "b.al" || mnem.starts_with("b.") || matches!(mnem, "cbz" | "cbnz" | "tbz" | "tbnz")
}

/// 处理一行（process!）。
pub fn process_line(st: &mut State, cmd: &str) -> EmuResult<()> {
    st.resolve_pending_branch(cmd)?;
    // 去 `#` 前缀（立即数）
    let cmd = cmd.trim();
    let mnem = mnemonic_of(cmd).to_string();
    if let Some(op) = compare_op(&mnem) {
        return handle_compare(st, op, cmd, &mnem);
    }
    if branch_mnem(&mnem) {
        return handle_branch(st, &mnem, cmd);
    }
    // 指令表查 + handler
    let Some((_, lo, hi)) = INSTRUCTIONS.iter().find(|(m, _, _)| *m == mnem) else {
        return Err(EmuError::UnsupportedInstruction(cmd.to_string()));
    };
    let args = operands(cmd);
    if args.len() < *lo || args.len() > *hi {
        return Err(EmuError::InstructionArgument(format!(
            "Incorrect argument number in {cmd}, expect: {lo}..{hi}"
        )));
    }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match mnem.as_str() {
        "add" => inst_add(st, &refs),
        "sub" => inst_sub(st, &refs),
        "adrp" => inst_adrp(st, &refs),
        "ldr" => inst_ldr(st, &refs),
        "ldrb" => inst_ldrb(st, &refs),
        "str" => inst_str(st, &refs),
        "stp" => inst_stp(st, &refs),
        "mov" => inst_mov(st, &refs),
        "mvn" => inst_mvn(st, &refs),
        "and" | "orr" | "eor" | "lsl" | "lsr" => inst_data(st, &mnem, &refs),
        "bic" => inst_bic(st, &refs),
        "bl" => inst_bl(st, &refs),
        "nop" | "bti" | "dmb" | "dsb" | "isb" => Ok(()),
        _ => Err(EmuError::UnsupportedInstruction(cmd.to_string())),
    }
}

fn strip_hash(s: &str) -> &str {
    s.strip_prefix('#').unwrap_or(s)
}

/// operands()：剥 `#`；`<symbol>` 尾注仅 bl 保留（inst_bl 判终端调用需要）。
fn operands(cmd: &str) -> Vec<String> {
    let keep_sym = mnemonic_of(cmd) == "bl";
    let mut ops = split_operands(cmd);
    for o in ops.iter_mut() {
        *o = o.strip_prefix('#').unwrap_or(o).to_string();
        if !keep_sym {
            if let Some(lt) = o.find(" <") {
                *o = o[..lt].trim().to_string();
            }
        }
    }
    ops
}

/// handle_compare（arm_family：shifted operand 折叠）。
fn handle_compare(st: &mut State, op: CmpOp, cmd: &str, _mnem: &str) -> EmuResult<()> {
    let ops = operands(cmd);
    if ops.len() > 3 {
        return Ok(()); // master: return false
    }
    let mut rhs = st.operand_str(&ops[1])?;
    if ops.len() == 3 {
        let Some(shifted) = shifted_operand(&rhs, &ops[2]) else {
            return Ok(());
        };
        rhs = shifted;
    }
    let lhs = st.operand_str(&ops[0])?;
    st.record_compare(op, lhs, rhs);
    Ok(())
}

/// shifted_operand（`0x1` + `lsl 12` → `0x1000`）。
pub(crate) fn shifted_operand(rhs: &str, modifier: &str) -> Option<String> {
    let m = modifier.trim();
    let (kind, amt) = m.split_once(char::is_whitespace)?;
    let amt: u32 = amt.trim().parse().ok()?;
    if !matches!(kind, "lsl" | "lsr" | "asr") {
        return None;
    }
    let v = crate::lambda::parse_int_str(rhs)?;
    let shifted = if kind == "lsl" { v << amt } else { v >> amt };
    Some(hex(shifted))
}

fn handle_branch(st: &mut State, mnem: &str, cmd: &str) -> EmuResult<()> {
    let ops = operands(cmd);
    match mnem {
        "b" | "b.al" => Ok(()), // 无条件：stitched path 处理
        "cbz" => st.branch_on_zero(parse_u64(&ops[1]), &ops[0], false),
        "cbnz" => st.branch_on_zero(parse_u64(&ops[1]), &ops[0], true),
        "tbz" => st.branch_on_bit(parse_u64(&ops[2]), &ops[0], parse_bit(&ops[1]), false),
        "tbnz" => st.branch_on_bit(parse_u64(&ops[2]), &ops[0], parse_bit(&ops[1]), true),
        other => {
            let cc = &other[2..];
            let Some(rel) = cond_relation(cc) else {
                return Err(EmuError::UnsupportedInstructionArgument(format!("cond {cc}")));
            };
            st.branch_on_compare(rel, parse_u64(&ops[0]))
        }
    }
}

fn parse_u64(s: &str) -> u64 {
    let s = strip_hash(s);
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn parse_bit(s: &str) -> u32 {
    let s = strip_hash(s);
    s.trim().parse().unwrap_or(0)
}

fn inst_add(st: &mut State, args: &[&str]) -> EmuResult<()> {
    // add dst, src, op2[, mode]
    let (dst, src, op2, mode) = match args {
        [d, s] => (*d, *s, "", None),
        [d, s, o] => (*d, *s, *o, None),
        [d, s, o, m] => (*d, *s, *o, Some(*m)),
        _ => return Err(State::err_unsupported_pub("add", args)),
    };
    let op2 = modified_operand(st, op2, mode)?;
    st.arith(true, dst, src, &op2)
}

fn inst_sub(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let (dst, src, op2, mode) = match args {
        [d, s] => (*d, *s, "", None),
        [d, s, o] => (*d, *s, *o, None),
        [d, s, o, m] => (*d, *s, *o, Some(*m)),
        _ => return Err(State::err_unsupported_pub("sub", args)),
    };
    let op2 = modified_operand(st, op2, mode)?;
    st.arith(false, dst, src, &op2)
}

/// modified_operand（sxtw 原样；常量 shift 折叠；其余不支持）。
fn modified_operand(st: &State, op2: &str, mode: Option<&str>) -> EmuResult<String> {
    let Some(mode) = mode else { return Ok(op2.to_string()) };
    if mode == "sxtw" {
        return Ok(op2.to_string());
    }
    let val = st.value_of(op2)?;
    let Val::Int(v) = val else {
        return Err(EmuError::UnsupportedInstructionArgument(format!("shift on {op2}")));
    };
    shifted_operand(&hex(v), mode)
        .ok_or_else(|| EmuError::UnsupportedInstructionArgument(format!("modifier {mode}")))
}

fn inst_adrp(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, imm] = args else { return Err(State::err_unsupported_pub("adrp", args)) };
    st.check_register(dst)?;
    let off = parse_u64(imm) as i64;
    st.registers.set(dst, Val::Lambda(st.libc_base().add(off)));
    Ok(())
}

fn inst_ldr(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let (dst, src, index) = match args {
        [d, s] => (*d, *s, "0"),
        [d, s, i] => (*d, *s, *i),
        _ => return Err(State::err_unsupported_pub("ldr", args)),
    };
    st.check_register(dst)?;
    let src = st.resolve_int_regs(src);
    let val = st.arg_val(&src)?;
    let val = st.read_value(val);
    st.registers.set(dst, val);
    let Some(index) = crate::lambda::parse_int_str(index) else {
        return Err(State::err_unsupported_pub("ldr", args));
    };
    if src.ends_with('!') || index != 0 {
        // pre/post-index：base += immi + index
        let base = src.trim_end_matches('!');
        let Ok(Val::Lambda(l)) = super::parse_val(base, &st.reg_map()) else {
            return Err(State::err_unsupported_pub("ldr", args));
        };
        let reg = match &l.obj {
            super::Obj::Reg(r) => r.clone(),
            _ => return Err(State::err_unsupported_pub("ldr", args)),
        };
        let cur = st.registers.get(&reg);
        let nv = arith_val(cur, l.imm + index);
        st.registers.set(&reg, nv);
    }
    Ok(())
}

fn inst_ldrb(st: &mut State, args: &[&str]) -> EmuResult<()> {
    inst_ldr(st, args)?;
    // 一字节不可命名：clobbered
    let dst = args[0];
    st.registers.set(dst, Val::Clobbered);
    Ok(())
}

fn inst_str(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let (src, dst, index) = match args {
        [s, d] => (*s, *d, "0"),
        [s, d, i] => (*s, *d, *i),
        _ => return Err(State::err_unsupported_pub("str", args)),
    };
    st.check_register(src)?;
    let Some(index) = crate::lambda::parse_int_str(index) else {
        return Err(State::err_unsupported_pub("str", args));
    };
    let dst = st.resolve_int_regs(dst);
    let Ok(Val::Lambda(dl)) = super::parse_val(&dst, &st.reg_map()) else {
        return Err(State::err_unsupported_pub("str", args));
    };
    let dst_l = dl.ref_().map_err(|e| EmuError::InstructionArgument(e))?;
    let v = st.registers.get(src);
    st.track_write(dst_l.clone(), vec![v]);
    if dst.ends_with('!') || index != 0 {
        let base = dst.trim_end_matches('!');
        let Ok(Val::Lambda(l)) = super::parse_val(base, &st.reg_map()) else {
            return Err(State::err_unsupported_pub("str", args));
        };
        let reg = match &l.obj {
            super::Obj::Reg(r) => r.clone(),
            _ => return Err(State::err_unsupported_pub("str", args)),
        };
        let cur = st.registers.get(&reg);
        let nv = arith_val(cur, l.imm + index);
        st.registers.set(&reg, nv);
    }
    Ok(())
}

fn inst_stp(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [reg1, reg2, dst] = args else { return Err(State::err_unsupported_pub("stp", args)) };
    let reg64 = |r: &str| st.register(r) && r.starts_with('x');
    if !reg64(reg1) || !reg64(reg2) {
        return Err(State::err_unsupported_pub("stp", args));
    }
    let dst = st.resolve_int_regs(dst);
    let Ok(Val::Lambda(dl)) = super::parse_val(&dst, &st.reg_map()) else {
        return Err(State::err_unsupported_pub("stp", args));
    };
    let dst_l = dl.ref_().map_err(|e| EmuError::InstructionArgument(e))?;
    let v1 = st.registers.get(reg1);
    let v2 = st.registers.get(reg2);
    st.track_write(dst_l, vec![v1, v2]);
    if dst.ends_with('!') {
        let base = dst.trim_end_matches('!');
        let Ok(Val::Lambda(l)) = super::parse_val(base, &st.reg_map()) else {
            return Err(State::err_unsupported_pub("stp", args));
        };
        let reg = match &l.obj {
            super::Obj::Reg(r) => r.clone(),
            _ => return Err(State::err_unsupported_pub("stp", args)),
        };
        let cur = st.registers.get(&reg);
        let nv = arith_val(cur, l.imm);
        st.registers.set(&reg, nv);
    }
    Ok(())
}

fn inst_mov(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, src] = args else { return Err(State::err_unsupported_pub("mov", args)) };
    st.check_register(dst)?;
    let v = st.arg_val(src)?;
    st.registers.set(dst, v);
    Ok(())
}

fn inst_mvn(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, op2] = args else { return Err(State::err_unsupported_pub("mvn", args)) };
    st.check_register(dst)?;
    let c = st.complement("mvn", op2, args)?;
    st.registers.set(dst, Val::Int(c));
    Ok(())
}

fn inst_data(st: &mut State, mnem: &str, args: &[&str]) -> EmuResult<()> {
    let op = match mnem {
        "and" => '&',
        "orr" => '|',
        "eor" => '^',
        "lsl" => '<',
        "lsr" => '>',
        _ => unreachable!(),
    };
    let (dst, src, op2) = match args {
        [d, s] => (*d, *s, ""),
        [d, s, o] => (*d, *s, *o),
        _ => return Err(State::err_unsupported_pub(mnem, args)),
    };
    st.data_op(op, dst, src, op2, mnem)
}

fn inst_bic(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let (dst, src, op2) = match args {
        [d, s, o] => (*d, *s, *o),
        _ => return Err(State::err_unsupported_pub("bic", args)),
    };
    let comp = st.complement("bic", op2, args)?;
    st.data_op('&', dst, src, &hex(comp), "and")
}

fn inst_bl(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [addr] = args else { return Err(State::err_unsupported_pub("bl", args)) };
    // 终端调用判定：解析 <name>
    if let Some(start) = addr.find('<') {
        let name = addr[start + 1..].split('@').next().unwrap_or("");
        let name = name.strip_suffix('>').unwrap_or(name);
        if is_terminal_call(name) {
            return Err(st.reach_terminal_call(addr));
        }
    }
    st.dispatch_safe_call(addr)
}

/// arith_val：寄存器值 + imm（不检查寄存器；用于 pre/post-index 更新）。
fn arith_val(v: Val, imm: i64) -> Val {
    match v {
        Val::Int(i) => Val::Int(i + imm),
        Val::Lambda(l) => Val::Lambda(l.add(imm)),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stp_ldr_readback() {
        let mut st = new_state();
        process_line(&mut st, "0: stp x29, x30, [sp, -0x20]!").unwrap();
        // sp 更新 -0x20；槽位写入
        assert_eq!(st.registers.get("sp").to_string(), "sp-0x20");
        // ldr 读回
        process_line(&mut st, "4: ldr x0, [sp, #0]").unwrap();
        assert_eq!(st.registers.get("x0").to_string(), "x29");
    }

    #[test]
    fn test_adrp() {
        let mut st = new_state();
        process_line(&mut st, "0: adrp x0, 0x3d000").unwrap();
        assert_eq!(st.registers.get("x0").to_string(), "$base+0x3d000");
        // objdump 实际形式：无 # 前缀、带 <sym> 尾注
        process_line(&mut st, "4: adrp x0, 127000 <in6addr_any+0x2648>").unwrap();
        assert_eq!(st.registers.get("x0").to_string(), "$base+0x127000");
        process_line(&mut st, "8: add x0, x0, #0x7d0").unwrap();
        assert_eq!(st.registers.get("x0").to_string(), "$base+0x1277d0");
    }

    #[test]
    fn test_cmp_bne_constraint() {
        let mut st = new_state();
        process_line(&mut st, "0: cmp x2, #1").unwrap();
        process_line(&mut st, "4: b.ne 0x10 <foo>").unwrap();
        // 下一行地址 8 ≠ 0x10 → 未跳转 → x2 == 0x1
        process_line(&mut st, "8: nop").unwrap();
        let cons = st.constraints();
        assert!(cons.contains(&"x2 == 0x1".to_string()), "{cons:?}");
    }

    #[test]
    fn test_cbz() {
        let mut st = new_state();
        process_line(&mut st, "0: cbz x0, 0x8").unwrap();
        process_line(&mut st, "4: nop").unwrap(); // 未跳转 → x0 != 0
        let cons = st.constraints();
        assert!(cons.contains(&"x0 != 0x0".to_string()), "{cons:?}");
    }

    #[test]
    fn test_bl_terminal() {
        let mut st = new_state();
        let r = process_line(&mut st, "0: bl 3f288 <execve>");
        assert!(r.is_err());
        assert_eq!(st.registers.get("pc").to_string(), "3f288 <execve>");
    }

    #[test]
    fn test_bl_safe_call() {
        let mut st = new_state();
        process_line(&mut st, "0: mov x1, #0").unwrap();
        process_line(&mut st, "4: bl 100 <sigprocmask>").unwrap();
        // caller-saved clobber；x1 曾是 0 → nullable ok
        assert_eq!(st.registers.get("x0"), Val::Int(0)); // 返回寄存器置 0
        assert!(matches!(st.registers.get("x9"), Val::Clobbered));
    }

    #[test]
    fn test_tbz() {
        let mut st = new_state();
        process_line(&mut st, "0: tbz w0, #4, 0x10").unwrap();
        process_line(&mut st, "4: nop").unwrap();
        let cons = st.constraints();
        assert!(cons.contains(&"(w0 & 0x10) != 0x0".to_string()), "{cons:?}");
    }

    #[test]
    fn test_str_folding_writable() {
        // master 语义：add x19, x20, #0x338 后 str [x19+4]
        // → dst_l 折叠为 x20+0x33c → 与 x20+0x338 同 base 取最小 offset
        let mut st = new_state();
        process_line(&mut st, "0: add x19, x20, #0x338").unwrap();
        process_line(&mut st, "4: str wzr, [x19, #0x4]").unwrap();
        let cons = st.constraints();
        assert_eq!(cons, vec!["writable: x20+0x33c".to_string()], "{cons:?}");

        let mut st2 = new_state();
        process_line(&mut st2, "0: add x19, x20, #0x338").unwrap();
        process_line(&mut st2, "4: str wzr, [x20, #0x338]").unwrap();
        process_line(&mut st2, "8: str wzr, [x19, #0x4]").unwrap();
        let cons2 = st2.constraints();
        assert_eq!(cons2, vec!["writable: x20+0x338".to_string()], "{cons2:?}");
    }
}
