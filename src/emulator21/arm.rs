//! arm（A32/Thumb-2）模拟器（master emulators/arm.rb + arm_family.rb 的 32 位部分）。

use super::mixins::shorthand;
use super::processor::*;
use super::{parse_val, Lambda, Val};
use crate::abi::AbiArch;
use std::cell::RefCell;
use std::rc::Rc;

/// 支持指令表（arm.rb#instructions：(名, 最小参数, 最大参数)）。
pub(crate) const INSTRUCTIONS: &[(&str, usize, usize)] = &[
    ("push", 1, 1),
    ("pop", 1, 1),
    ("add", 2, 3),
    ("sub", 2, 3),
    ("mov", 2, 2),
    ("ldr", 2, 3),
    ("ldrb", 2, 3),
    ("str", 2, 3),
    ("bl", 1, 1),
    ("blx", 1, 1),
    ("nop", 0, 1),
    ("dmb", 0, 1),
    ("dsb", 0, 1),
    ("isb", 0, 1),
    ("and", 2, 3),
    ("orr", 2, 3),
    ("eor", 2, 3),
    ("bic", 2, 3),
    ("mvn", 2, 2),
    ("lsl", 2, 3),
    ("lsr", 2, 3),
    ("cmp", 2, 3),
    ("cmn", 2, 3),
    ("tst", 2, 3),
    ("svc", 1, 1),
];

// 目标 libc 字节（literal pool 读取）。find() 开始时设置一次。
thread_local! {
    static FILE: RefCell<Option<Rc<Vec<u8>>>> = const { RefCell::new(None) };
}

pub fn set_file(data: Rc<Vec<u8>>) {
    FILE.with(|f| *f.borrow_mut() = Some(data));
}

pub fn new_state() -> State {
    State::new(AbiArch::Arm, "sp", "pc", None)
}

/// COMPARES：cmp→sub、cmn→add、tst→and（arm_family）。
fn compare_op(mnem: &str) -> Option<CmpOp> {
    match mnem {
        "cmp" => Some(CmpOp::Sub),
        "cmn" => Some(CmpOp::Add),
        "tst" => Some(CmpOp::And),
        _ => None,
    }
}

/// FLAG_SETTING：movs/adds/... → 基础助记符。
fn strip_flag_setting(mnem: &str) -> &str {
    const BASES: &[&str] = &["mov", "add", "sub", "and", "orr", "eor", "bic", "mvn", "lsl", "lsr"];
    for b in BASES {
        if mnem.len() == b.len() + 1 && mnem.starts_with(b) && mnem.ends_with('s') {
            return b;
        }
    }
    mnem
}

fn branch_mnem(mnem: &str) -> bool {
    // arm.rb#branch_mnem?：b、cbz/cbnz、b<cond>（COND ∪ vs/vc）
    if mnem == "b" || matches!(mnem, "cbz" | "cbnz") {
        return true;
    }
    if let Some(cc) = mnem.strip_prefix('b') {
        return super::aarch64::cond_relation(cc).is_some() || matches!(cc, "vs" | "vc");
    }
    false
}

/// 处理一行（process!）。
pub fn process_line(st: &mut State, cmd: &str) -> EmuResult<()> {
    st.resolve_pending_branch(cmd)?;
    let line = cmd.trim();
    track_mode(st, line);
    let (body, literal) = split_line(line);
    st.literal = literal;
    let body = normalize(&body);
    let (mnem, rest) = match body.split_once(char::is_whitespace) {
        Some((m, r)) => (m, r),
        None => (body.as_str(), ""),
    };
    if let Some(op) = compare_op(mnem) {
        return handle_compare(st, op, rest);
    }
    if branch_mnem(mnem) {
        return handle_branch(st, mnem, rest);
    }
    if mnem == "push" || mnem == "pop" {
        return if mnem == "push" { inst_push(st, rest) } else { inst_pop(st, rest) };
    }
    // master parse 的子串回退：未知助记符在 body 里找 `<inst> ` 首个命中者
    // （`vmov r2, s18` 命中 `mov ` → 当 mov 处理；条件后缀 ldrne/addcc 不命中）
    let (name, lo, hi, args_body): (&str, usize, usize, String) = {
        match INSTRUCTIONS.iter().find(|(m, _, _)| *m == mnem) {
            Some((m, lo, hi)) => (m, *lo, *hi, body.clone()),
            None => {
                let body_ws = if rest.is_empty() {
                    mnem.to_string()
                } else {
                    format!("{mnem} {rest}")
                };
                let found = INSTRUCTIONS.iter().find(|(m, _, _)| {
                    body_ws.find(&format!("{m} ")).map(|_| true).unwrap_or(false)
                        || body_ws.ends_with(m)
                });
                let Some((m, lo, hi)) = found else {
                    return Err(EmuError::UnsupportedInstruction(cmd.to_string()));
                };
                let idx = body_ws.find(&format!("{m} ")).map(|i| i + m.len()).unwrap_or(body_ws.len());
                // split_operands 会跳过首个 token（助记符）—— 前置哑元对齐
                (m, *lo, *hi, format!("x{}", &body_ws[idx..]))
            }
        }
    };
    let args = split_operands(&args_body);
    if args.len() < lo || args.len() > hi {
        return Err(EmuError::InstructionArgument(format!(
            "Incorrect argument number in {cmd}, expect: {lo}..{hi}"
        )));
    }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match name {
        "add" => inst_add(st, &refs),
        "sub" => inst_sub(st, &refs),
        "mov" => inst_mov(st, &refs),
        "ldr" => inst_ldr(st, &refs),
        "ldrb" => inst_ldrb(st, &refs),
        "str" => inst_str(st, &refs),
        "mvn" => inst_mvn(st, &refs),
        "and" | "orr" | "eor" | "lsl" | "lsr" => inst_data(st, mnem, &refs),
        "bic" => inst_bic(st, &refs),
        "bl" | "blx" => inst_bl(st, &refs),
        "nop" | "dmb" | "dsb" | "isb" | "svc" => Ok(()),
        _ => Err(EmuError::UnsupportedInstruction(cmd.to_string())),
    }
}

/// track_mode：.w/.n 后缀或 2 字节步距证明 thumb；记录 cur_addr。
fn track_mode(st: &mut State, line: &str) {
    // .w/.n 后缀
    let s = line.trim_start();
    if let Some(c) = s.find(':') {
        let body = s[c + 1..].trim_start();
        let mnem = body.split_whitespace().next().unwrap_or("");
        if let Some(stripped) = mnem.strip_suffix(".w").or_else(|| mnem.strip_suffix(".n")) {
            let _ = stripped;
            st.thumb = true;
        }
    }
    let Some(addr) = line_addr_of(line) else { return };
    st.line_addr = addr;
    if st.prev_addr != 0 && addr.wrapping_sub(st.prev_addr) == 2 {
        st.thumb = true;
    }
    st.prev_addr = addr;
    // value_of(pc) 覆写：pc 寄存器读值为 $base+addr+bias（文字替换不可行——
    // parse_val 不认 $base 文本；寄存器表预置即等效）
    let pc_v = pc_value(st);
    st.registers.set("pc", pc_v);
}

fn line_addr_of(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let end = s.find(':')?;
    if end == 0 || !s[..end].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(&s[..end], 16).ok()
}

/// note_instruction_set：整候选判定 thumb（首条指令读 pc 前定型）。
pub fn note_instruction_set(st: &mut State, cmds: &[String]) {
    if st.thumb {
        return;
    }
    let any_suffix = cmds.iter().any(|l| {
        let s = l.trim_start();
        let Some(c) = s.find(':') else { return false };
        let body = s[c + 1..].trim_start();
        let Some(m) = body.split_whitespace().next() else { return false };
        m.ends_with(".w") || m.ends_with(".n")
    });
    if any_suffix {
        st.thumb = true;
        return;
    }
    let addrs: Vec<u64> = cmds.iter().filter_map(|l| line_addr_of(l)).collect();
    if addrs.windows(2).any(|w| w[1].wrapping_sub(w[0]) == 2) {
        st.thumb = true;
    }
}

/// split_line：去地址前缀，提取 literal 地址，去行尾注释。
/// `@ (2c6a8 <x>)` / `@ (0x2c6a8)` / `@ 2c6a8` → Some(0x2c6a8)。
fn split_line(line: &str) -> (String, Option<u64>) {
    let body = line.trim_start();
    let body = match body.find(':') {
        Some(c) if body[..c].chars().all(|x| x.is_ascii_hexdigit()) && !body[..c].is_empty() => {
            &body[c + 1..]
        }
        _ => body,
    };
    let body = body.trim();
    let literal = extract_literal(body);
    // 去行尾注释：空白前置的 @ 或 ;（不吞 <sym@@VER> 里的 @@）
    let stripped = match body.find(|c| c == '@' || c == ';') {
        Some(pos) if pos > 0 && body[..pos].ends_with(char::is_whitespace) => &body[..pos],
        _ => body,
    };
    (stripped.trim().to_string(), literal)
}

fn extract_literal(body: &str) -> Option<u64> {
    // /\@\s*\(?(?:0x)?([0-9a-f]+)(?:[\s)]|\z)/
    let mut rest = body;
    while let Some(pos) = rest.find('@') {
        let after = &rest[pos + 1..];
        let after = after.trim_start();
        let after = after.strip_prefix('(').unwrap_or(after);
        let after = after.strip_prefix("0x").unwrap_or(after);
        let tok: String = after.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if !tok.is_empty() {
            let next = after.chars().nth(tok.len());
            if next.is_none() || matches!(next, Some(' ') | Some(')') | Some('\t')) {
                return u64::from_str_radix(&tok, 16).ok();
            }
        }
        rest = &rest[pos + 1..];
    }
    None
}

/// normalize：去 .w/.n、flags-s 别名回基础名、去立即数 `#`。
fn normalize(body: &str) -> String {
    let (mnem, rest) = match body.split_once(char::is_whitespace) {
        Some((m, r)) => (m, Some(r)),
        None => (body, None),
    };
    let mnem = mnem.strip_suffix(".w").or_else(|| mnem.strip_suffix(".n")).unwrap_or(mnem);
    let mnem = strip_flag_setting(mnem);
    let rest = match rest {
        Some(r) => strip_immediates(r),
        None => String::new(),
    };
    if rest.is_empty() {
        mnem.to_string()
    } else {
        format!("{mnem} {rest}")
    }
}

/// 去 `#(-?0x?hex)` 前缀的 #（normalize 的 gsub）。
fn strip_immediates(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'#' && i + 1 < b.len() {
            let mut j = i + 1;
            if b[j] == b'-' {
                j += 1;
            }
            let hex_start = j;
            if j + 1 < b.len() && b[j] == b'0' && (b[j + 1] == b'x' || b[j + 1] == b'X') {
                j += 2;
            }
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > hex_start && !s[hex_start..j].is_empty() && (j == i + 1 + (j - i - 1)) && j - i >= 2 {
                // 数字：跳过 '#'
                out.push_str(&s[i + 1..j]);
                i = j;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// pc 读值：$base + addr + bias（thumb 4 / A32 8）。
fn pc_value(st: &State) -> Val {
    let bias = if st.thumb { 4 } else { 8 };
    Val::Lambda(st.libc_base().add(st.line_addr as i64 + bias))
}

/// handle_compare（arm_family：shifted operand 折叠）。
fn handle_compare(st: &mut State, op: CmpOp, rest: &str) -> EmuResult<()> {
    let ops = annotation_stripped(rest);
    if ops.len() > 3 {
        return Ok(());
    }
    let mut rhs = st.operand_str(&ops[1])?;
    if ops.len() == 3 {
        let Some(shifted) = super::aarch64::shifted_operand(&rhs, ops[2].trim()) else {
            return Ok(());
        };
        rhs = shifted;
    }
    let lhs = st.operand_str(&ops[0])?;
    st.record_compare(op, lhs, rhs);
    Ok(())
}

/// operands()：逗号切分 + `<...>` 尾注剥离（分支操作数用）。
fn annotation_stripped(rest: &str) -> Vec<String> {
    rest.split(',')
        .map(|o| {
            let o = o.trim();
            match o.find(" <") {
                Some(p) => o[..p].trim().to_string(),
                None => o.to_string(),
            }
        })
        .collect()
}

fn parse_u64(s: &str) -> u64 {
    let s = s.trim().trim_start_matches('#');
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn handle_branch(st: &mut State, mnem: &str, rest: &str) -> EmuResult<()> {
    let ops = annotation_stripped(rest);
    match mnem {
        "b" => Ok(()), // 无条件：stitched path 处理
        "cbz" => st.branch_on_zero(parse_u64(&ops[1]), &ops[0], false),
        "cbnz" => st.branch_on_zero(parse_u64(&ops[1]), &ops[0], true),
        other => {
            let cc = &other[1..];
            let Some(rel) = super::aarch64::cond_relation(cc) else {
                // vs/vc：无约束形式 → 中止路径
                return Err(EmuError::UnsupportedInstructionArgument(format!("cond {cc}")));
            };
            st.branch_on_compare(rel, parse_u64(&ops[0]))
        }
    }
}

fn inst_add(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let (dst, src, op2) = match args {
        [d, s] => (*d, *s, ""),
        [d, s, o] => (*d, *s, *o),
        _ => return Err(State::err_unsupported_pub("add", args)),
    };
    st.arith(true, dst, src, op2)
}

fn inst_sub(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let (dst, src, op2) = match args {
        [d, s] => (*d, *s, ""),
        [d, s, o] => (*d, *s, *o),
        _ => return Err(State::err_unsupported_pub("sub", args)),
    };
    st.arith(false, dst, src, op2)
}

fn inst_mov(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, src] = args else { return Err(State::err_unsupported_pub("mov", args)) };
    st.check_register(dst)?;
    let v = st.arg_val(src)?;
    st.registers.set(dst, v);
    Ok(())
}

/// literal pool 读值（LE u32；vaddr 当文件偏移用 —— 与 master File#[] 一致）。
fn literal_value(st: &State) -> EmuResult<Val> {
    let Some(lit) = st.literal else {
        return Err(EmuError::UnsupportedInstructionArgument("ldr pc".into()));
    };
    FILE.with(|f| {
        let b = f.borrow();
        let Some(data) = b.as_ref() else {
            return Err(EmuError::UnsupportedInstructionArgument("ldr pc".into()));
        };
        let off = lit as usize;
        if off + 4 > data.len() {
            return Err(EmuError::UnsupportedInstructionArgument("ldr pc".into()));
        }
        let v = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        Ok(Val::Int(v as i64))
    })
}

fn inst_ldr(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let (dst, src, index) = match args {
        [d, s] => (*d, *s, "0"),
        [d, s, i] => (*d, *s, *i),
        _ => return Err(State::err_unsupported_pub("ldr", args)),
    };
    st.check_register(dst)?;
    let Some(index) = crate::lambda::parse_int_str(index) else {
        return Err(State::err_unsupported_pub("ldr", args));
    };
    let val = if src.contains("pc") {
        literal_value(st)?
    } else {
        let resolved = st.resolve_int_regs(src);
        let v = parse_val(&resolved, &st.reg_map()).map_err(|_| EmuError::InstructionArgument("parse".into()))?;
        st.read_value(v)
    };
    st.registers.set(dst, val);
    if src.ends_with('!') || index != 0 {
        writeback(st, src, index)?;
    }
    Ok(())
}

fn inst_ldrb(st: &mut State, args: &[&str]) -> EmuResult<()> {
    inst_ldr(st, args)?;
    // 一字节不可命名：clobbered
    st.registers.set(args[0], Val::Clobbered);
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
    let resolved = st.resolve_int_regs(dst);
    let v = parse_val(&resolved, &st.reg_map()).map_err(|_| EmuError::InstructionArgument("parse".into()))?;
    let Val::Lambda(dl) = v else {
        return Err(State::err_unsupported_pub("str", args));
    };
    let dst_l = dl.ref_().map_err(|_| EmuError::InstructionArgument("parse".into()))?;
    let val = st.registers.get(src);
    st.track_write(dst_l, vec![val]);
    if dst.ends_with('!') || index != 0 {
        writeback(st, dst, index)?;
    }
    Ok(())
}

/// pre/post-index 回写：`[reg, imm]!` / `[reg], imm` → reg += immi + index。
fn writeback(st: &mut State, mem: &str, index: i64) -> EmuResult<()> {
    let trimmed = mem.trim_end_matches('!');
    let resolved = st.resolve_int_regs(trimmed);
    let v = parse_val(&resolved, &st.reg_map()).map_err(|_| EmuError::InstructionArgument("parse".into()))?;
    let Val::Lambda(l) = v else {
        return Err(EmuError::InstructionArgument("writeback".into()));
    };
    if let Some(reg) = l.root_name() {
        if st.register(&reg) {
            let cur = st.registers.get(&reg);
            let nv = arith_val(cur, l.imm + index);
            st.registers.set(&reg, nv);
        }
    }
    Ok(())
}

/// 寄存器值 + imm（回写更新）。
fn arith_val(v: Val, imm: i64) -> Val {
    match v {
        Val::Int(i) => Val::Int(i + imm),
        Val::Lambda(l) => Val::Lambda(l.add(imm)),
        other => other,
    }
}

/// reglist：`{r4, r5, lr}` → [r4, r5, lr]。
fn reglist(list: &str) -> Vec<String> {
    list.trim_matches(|c| c == '{' || c == '}')
        .split(',')
        .map(|s| s.trim().to_string())
        .collect()
}

/// push {regs}：sp -= 4n；[sp+0..4n) 依次写入（最低号寄存器在最低地址）。
fn inst_push(st: &mut State, list: &str) -> EmuResult<()> {
    let regs = reglist(list);
    let n = regs.len() as i64;
    let size_t = st.size_t();
    let sp = st.sp.clone();
    let cur = st.registers.get(&sp);
    let Val::Lambda(sp_l) = cur else {
        return Err(EmuError::InstructionArgument("push".into()));
    };
    let new_sp = Val::Lambda(sp_l.add(-size_t * n));
    st.registers.set(&sp, new_sp.clone());
    // base = evaluate({sp:0})：entry sp → 偏移量
    let Val::Lambda(nl) = new_sp else { unreachable!() };
    let base = offset_of(&nl, &sp).ok_or_else(|| EmuError::InstructionArgument("push".into()))?;
    for (i, r) in regs.iter().enumerate() {
        let val = st.registers.get(r);
        st.track_write(Lambda::reg(&sp).add(base + size_t * i as i64), vec![val]);
    }
    Ok(())
}

/// pop {regs}：[sp+0..4n) 依次读回；sp += 4n。pc/lr 弹出不影响约束。
fn inst_pop(st: &mut State, list: &str) -> EmuResult<()> {
    let regs = reglist(list);
    let size_t = st.size_t();
    let sp = st.sp.clone();
    let cur = st.registers.get(&sp);
    let Val::Lambda(sp_l) = cur else {
        return Err(EmuError::InstructionArgument("pop".into()));
    };
    let base = offset_of(&sp_l, &sp).ok_or_else(|| EmuError::InstructionArgument("pop".into()))?;
    for (i, r) in regs.iter().enumerate() {
        if st.register(r) && r != "pc" {
            let val = st
                .stack_of(&sp)
                .and_then(|m| m.get(&(base + size_t * i as i64)).cloned())
                .unwrap_or(Val::Clobbered);
            st.registers.set(r, val);
        }
    }
    let new_sp = Val::Lambda(sp_l.add(size_t * regs.len() as i64));
    st.registers.set(&sp, new_sp);
    Ok(())
}

/// entry 形式 lambda（obj==reg、无 deref/op）的偏移；其余 None。
fn offset_of(l: &super::Lambda, reg: &str) -> Option<i64> {
    match &l.obj {
        super::Obj::Reg(r) if r == reg && l.deref_count == 0 && l.op.is_none() => Some(l.imm),
        _ => None,
    }
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
        [d, s] => (*d, *s, ""),
        [d, s, o] => (*d, *s, *o),
        _ => return Err(State::err_unsupported_pub("bic", args)),
    };
    let (src, op2) = shorthand(dst, src, op2);
    let comp = st.complement("bic", op2, args)?;
    st.data_op('&', dst, src, &super::hex(comp), "and")
}

fn inst_bl(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [addr] = args else { return Err(State::err_unsupported_pub("bl", args)) };
    if let Some(start) = addr.find('<') {
        let name = addr[start + 1..].split('@').next().unwrap_or("");
        let name = name.strip_suffix('>').unwrap_or(name);
        if is_terminal_call(name) {
            return Err(st.reach_terminal_call(addr));
        }
    }
    st.dispatch_safe_call(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_line() {
        let (b, l) = split_line("2c626:\tldr r2, [pc, #128]\t@ (2c6a8 <x>)");
        assert_eq!(b, "ldr r2, [pc, #128]");
        assert_eq!(l, Some(0x2c6a8));
        let (b, l) = split_line("2c626:\tldr.w r2, [pc, #128]\t@ 2c6a8");
        assert_eq!(b, "ldr.w r2, [pc, #128]");
        assert_eq!(l, Some(0x2c6a8));
        // @@GLIBC 不误吞
        let (b, l) = split_line("3980c:\tbl 498bc <__woverflow@@GLIBC_2.4>");
        assert_eq!(b, "bl 498bc <__woverflow@@GLIBC_2.4>");
        assert_eq!(l, None);
    }

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("movs r0, #0"), "mov r0, 0");
        assert_eq!(normalize("add.w r0, r4, #8"), "add r0, r4, 8");
        assert_eq!(normalize("bne 2c438"), "bne 2c438");
        assert_eq!(normalize("cmp r3, #254"), "cmp r3, 254");
    }

    #[test]
    fn test_thumb_pc_bias() {
        let mut st = new_state();
        note_instruction_set(
            &mut st,
            &["4a1c0: ldr r0, [pc, #8]".into(), "4a1c2: add r0, pc".into()],
        );
        assert!(st.thumb);
        process_line(&mut st, "4a1c2: mov r0, pc").unwrap();
        assert_eq!(st.registers.get("r0").to_string(), "$base+0x4a1c6");
    }

    #[test]
    fn test_push_pop() {
        let mut st = new_state();
        process_line(&mut st, "2c208: push {r4, r5, r6, r7, lr}").unwrap();
        assert_eq!(st.registers.get("sp").to_string(), "sp-0x14");
        process_line(&mut st, "2c20a: pop {r4, r5}").unwrap();
        assert_eq!(st.registers.get("sp").to_string(), "sp-0xc");
    }

    #[test]
    fn test_cmp_bne() {
        let mut st = new_state();
        process_line(&mut st, "0: cmp r3, #3").unwrap();
        process_line(&mut st, "4: bne c").unwrap();
        process_line(&mut st, "8: nop").unwrap();
        let cons = st.constraints();
        assert!(cons.contains(&"r3 == 0x3".to_string()), "{cons:?}");
    }

    #[test]
    fn test_add_pc_two_op() {
        let mut st = new_state();
        note_instruction_set(&mut st, &["2d3a4: movs r0, r1".into(), "2d3a6: add r0, pc".into()]);
        let r = process_line(&mut st, "2d3a6: add r0, pc");
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(st.registers.get("r0").to_string(), "(r0 + $base+0x2d3aa)");
    }

    #[test]
    fn test_pipeline_seq() {
        // literal pool 读取需要真实 libc 字节；样本缺失时跳过（不依赖绝对路径）
        let Some(path) = crate::search21::samples_libc_path("glibc/arm/libc-2.27-3ubuntu1.5.so") else {
            eprintln!("sample missing, skip test_pipeline_seq");
            return;
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("sample unreadable, skip test_pipeline_seq");
                return;
            }
        };
        crate::emulator21::arm::set_file(std::rc::Rc::new(bytes));
        let mut st = new_state();
        let lines = [
            " 2d39c:\tldr\tr2, [pc, #128]\t@ (2d420 <__strtod_nan@@GLIBC_PRIVATE+0x468>)",
            " 2d39e:\tmov\tr1, r4",
            " 2d3a0:\tldr\tr0, [pc, #128]\t@ (2d424 <__strtod_nan@@GLIBC_PRIVATE+0x46c>)",
            " 2d3a2:\tstr\tr3, [r6, #0]",
            " 2d3a4:\tstr\tr3, [r6, #4]",
            " 2d3a6:\tadd\tr0, pc",
        ];
        note_instruction_set(&mut st, &lines.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        for l in lines {
            let r = process_line(&mut st, l);
            assert!(r.is_ok(), "{l} -> {r:?}");
        }
        // Int(0xa884e) + $base+0x2d3aa = $base+0xd5af8
        assert_eq!(st.registers.get("r0").to_string(), "$base+0xd5af8");
    }

    #[test]
    fn test_bl_terminal() {
        let mut st = new_state();
        let r = process_line(&mut st, "0: bl 3f4e0 <execve>");
        assert!(r.is_err());
        assert_eq!(st.registers.get("pc").to_string(), "3f4e0 <execve>");
    }
}
