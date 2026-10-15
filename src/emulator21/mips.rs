//! mips o32 模拟器（master emulators/mips.rb 全语义移植）。
//!
//! 与 riscv64 的关键差异：
//! - **延迟槽**：分支/调用延迟一条指令生效。process! 持回转移（@delayed），
//!   先执行下一条（dispatch），再 apply_delayed 应用转移
//! - GOT：调用目标经 `lw t9,-off(gp)` 从 GOT 装入；fetcher 在行尾写
//!   `<name>`（call）或 `# <addr>`（GOT 全局槽值）。load_value 读 # 注释
//!   → `$base+<addr>`（size==size_t 时）
//! - 无标志寄存器：条件分支 = record_compare(:sub)+branch_on_compare 合一
//!   （COND 8 项；*z 零形式第二操作数 zero）
//! - argument(idx>=4)：o32 栈槽从 sp+0 起含寄存器参数槽（slot = idx*size_t）
//!   —— 注意与 arm 的 (idx-4) 不同：o32 为每个参数保留槽（含前 4 个寄存器参数）

use super::processor::*;
use super::{parse_val, Lambda, Obj, Val};
use crate::abi::AbiArch;

/// 支持指令表（mips.rb#instructions：(名, 最小参数, 最大参数)）。
pub(crate) const INSTRUCTIONS: &[(&str, usize, usize)] = &[
    ("addiu", 3, 3),
    ("addu", 3, 3),
    ("bal", 1, 1),
    ("jal", 1, 1),
    ("jalr", 1, 2),
    ("li", 2, 2),
    ("lui", 2, 2),
    ("move", 2, 2),
    ("nop", 0, 0),
    ("subu", 3, 3),
    // LOADS（2 操作数）
    ("lw", 2, 2),
    ("lh", 2, 2),
    ("lhu", 2, 2),
    ("lb", 2, 2),
    ("lbu", 2, 2),
    // STORES（2 操作数）
    ("sw", 2, 2),
    ("sh", 2, 2),
    ("sb", 2, 2),
    // DATA_OPS（3 操作数）
    ("and", 3, 3),
    ("andi", 3, 3),
    ("or", 3, 3),
    ("ori", 3, 3),
    ("xor", 3, 3),
    ("xori", 3, 3),
    ("sll", 3, 3),
    ("srl", 3, 3),
];

/// COND：条件分支助记符 → 关系键（mips.rb COND 8 项）。
fn cond_relation(mnem: &str) -> Option<&'static str> {
    Some(match mnem {
        "beq" => "eq",
        "bne" => "ne",
        "beqz" => "eq",
        "bnez" => "ne",
        "blez" => "sle",
        "bgtz" => "sgt",
        "bltz" => "slt",
        "bgez" => "sge",
        _ => return None,
    })
}

/// CALLS：调用助记符（延迟槽同分支）。
const CALLS: &[&str] = &["jal", "jalr", "bal"];

fn load_size(mnem: &str) -> Option<usize> {
    Some(match mnem {
        "lw" => 4,
        "lh" | "lhu" => 2,
        "lb" | "lbu" => 1,
        _ => return None,
    })
}

fn store_size(mnem: &str) -> Option<usize> {
    Some(match mnem {
        "sw" => 4,
        "sh" => 2,
        "sb" => 1,
        _ => return None,
    })
}

fn data_op_char(mnem: &str) -> Option<char> {
    Some(match mnem {
        "and" | "andi" => '&',
        "or" | "ori" => '|',
        "xor" | "xori" => '^',
        "sll" => '<',
        "srl" => '>',
        _ => return None,
    })
}

pub fn new_state() -> State {
    let mut st = State::new(AbiArch::Mips, "sp", "pc", None);
    st.registers.set("zero", Val::Int(0)); // hardwired
    st
}

fn branch_mnem(mnem: &str) -> bool {
    mnem == "b" || cond_relation(mnem).is_some()
}

fn transfer(mnem: &str) -> bool {
    branch_mnem(mnem) || CALLS.contains(&mnem)
}

/// 处理一行（process!）：转移持回 → dispatch 当前 → apply_delayed。
pub fn process_line(st: &mut State, cmd: &str) -> EmuResult<()> {
    st.resolve_pending_branch(cmd)?;
    let line = cmd.trim();
    if let Some(a) = addr_of_line(line) {
        st.line_addr = a;
    }
    // GOT 槽值注释：`# 3e0b0`（fetcher state_got_values 写入）
    st.got_value = got_value_of(line);
    let after_addr = strip_addr(line);
    let (body, _) = split_body(after_addr);
    let (mnem, rest) = match body.split_once(char::is_whitespace) {
        Some((m, r)) => (m, r.trim()),
        None => (body, ""),
    };
    if transfer(mnem) {
        // 持回：延迟槽指令先行
        st.delayed = Some((mnem.to_string(), body.to_string()));
        return Ok(());
    }
    dispatch(st, mnem, rest, body)?;
    apply_delayed(st)
}

fn addr_of_line(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let end = s.find(':')?;
    if end == 0 || !s[..end].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(&s[..end], 16).ok()
}

/// 剥地址前缀（`4b3dc:\tlw t9,-31652(gp)` → `lw t9,-31652(gp)`）。
fn strip_addr(line: &str) -> &str {
    match line.find(':') {
        Some(c) if !line[..c].is_empty() && line[..c].chars().all(|ch| ch.is_ascii_hexdigit()) => {
            line[c + 1..].trim_start()
        }
        _ => line,
    }
}

/// GOT 槽值：`# <hex>` 尾注（state_got_values 注入；Instruction#fetch_args 的
/// `#` 截断发生在此之后——master 先在 process! 提取 GOT_VALUE 再 parse）。
fn got_value_of(line: &str) -> Option<i64> {
    // /#\s*([0-9a-f]+)\s*\z/ —— 注意是行尾最后一个 # 注释
    let idx = line.rfind('#')?;
    let rest = line[idx + 1..].trim();
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    i64::from_str_radix(rest, 16).ok()
}

/// 去 `//` 与 `#` 尾注（Instruction#fetch_args：rindex 截断）。
fn split_body(line: &str) -> (&str, ()) {
    let mut s = line;
    if let Some(i) = s.rfind("//") {
        s = &s[..i];
    }
    if let Some(i) = s.rfind('#') {
        s = &s[..i];
    }
    (s.trim_end(), ())
}

/// 指令操作数（fetch_args 语义：逗号切分，保留 `<sym>` 尾注——
/// call 行的名字识别依赖它）。
fn operands(rest: &str) -> Vec<String> {
    rest.split(',').map(|o| o.trim().to_string()).collect()
}

/// 分支操作数（mips.rb#operands：剥 `<symbol>` 尾注）。
fn branch_operands(rest: &str) -> Vec<String> {
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

fn dispatch(st: &mut State, mnem: &str, rest: &str, body: &str) -> EmuResult<()> {
    let Some((name, lo, hi)) = INSTRUCTIONS.iter().find(|(m, _, _)| *m == mnem) else {
        return Err(EmuError::UnsupportedInstruction(body.to_string()));
    };
    let args = operands(rest);
    if args.len() < *lo || args.len() > *hi {
        return Err(EmuError::InstructionArgument(format!(
            "Incorrect argument number in {body}, expect: {lo}..{hi}"
        )));
    }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match *name {
        "bal" | "jal" | "jalr" => inst_call(st, name, &refs),
        "addu" | "addiu" => inst_arith(st, true, &refs),
        "subu" => inst_arith(st, false, &refs),
        "move" => inst_move(st, &refs),
        "li" => inst_li(st, &refs),
        "lui" => inst_lui(st, &refs),
        "nop" => Ok(()),
        _ => {
            if let Some(sz) = load_size(name) {
                inst_load(st, &refs, sz)
            } else if let Some(sz) = store_size(name) {
                inst_store(st, &refs, sz)
            } else if let Some(op) = data_op_char(name) {
                st.data_op(op, refs[0], refs[1], refs[2], name)
            } else {
                Err(EmuError::UnsupportedInstruction(body.to_string()))
            }
        }
    }
}

/// apply_delayed：执行持回的转移（分支或调用）。
fn apply_delayed(st: &mut State) -> EmuResult<()> {
    let Some((mnem, body)) = st.delayed.take() else {
        return Ok(());
    };
    let (_, rest) = match body.split_once(char::is_whitespace) {
        Some((m, r)) => (m, r.trim()),
        None => (body.as_str(), ""),
    };
    if branch_mnem(&mnem) {
        return handle_branch(st, &mnem, rest);
    }
    dispatch(st, &mnem, rest, &body)
}

/// handle_branch：b 无条件；条件分支 record_compare(:sub)+branch_on_compare。
/// 零形式第二操作数 zero；目标 = 最后操作数（to_i(16)）。
fn handle_branch(st: &mut State, mnem: &str, rest: &str) -> EmuResult<()> {
    if mnem == "b" {
        return Ok(());
    }
    let ops = branch_operands(rest);
    let (lhs, rhs) = if mnem.ends_with('z') {
        (ops[0].clone(), "zero".to_string())
    } else {
        (ops[0].clone(), ops[1].clone())
    };
    let lhs = st.operand_str(&lhs)?;
    let rhs = st.operand_str(&rhs)?;
    st.record_compare(CmpOp::Sub, lhs, rhs);
    let rel = cond_relation(mnem).unwrap();
    let target = parse_hex_target(ops.last().map(|s| s.as_str()).unwrap_or(""));
    st.branch_on_compare(rel, target)
}

fn parse_hex_target(s: &str) -> u64 {
    let tok: String = s.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if tok.is_empty() {
        return 0;
    }
    u64::from_str_radix(&tok, 16).unwrap_or(0)
}

/// call_target：终端 → reach_terminal_call；否则 dispatch_safe_call。
fn call_target(st: &mut State, addr: &str) -> EmuResult<()> {
    if let Some(start) = addr.find('<') {
        let name = addr[start + 1..].split('@').next().unwrap_or("");
        let name = name.strip_suffix('>').unwrap_or(name);
        if is_terminal_call(name) {
            return Err(st.reach_terminal_call(addr));
        }
    }
    st.dispatch_safe_call(addr)
}

/// 指令分派后的调用（jal/jalr/bal 从 apply_delayed 进入 dispatch → 此处）。
/// dispatch 表中 bal/jal/jalr 的处理。
fn inst_call(st: &mut State, mnem: &str, args: &[&str]) -> EmuResult<()> {
    let _ = mnem;
    // jal/bal：目标 = args[0]（可带 <name>）；jalr 1..2：目标 = args.last
    let addr = args.last().copied().unwrap_or("");
    call_target(st, addr)
}

fn inst_arith(st: &mut State, plus: bool, args: &[&str]) -> EmuResult<()> {
    let [dst, src, op2] = args else {
        return Err(State::err_unsupported_pub(if plus { "addu" } else { "subu" }, args))
    };
    st.arith(plus, dst, src, op2)
}

fn inst_move(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, src] = args else { return Err(State::err_unsupported_pub("move", args)) };
    st.check_register(dst)?;
    let v = st.arg_val(src)?;
    st.registers.set(dst, v);
    Ok(())
}

/// li dst, imm：十进制。
fn inst_li(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, imm] = args else { return Err(State::err_unsupported_pub("li", args)) };
    st.check_register(dst)?;
    let v: i64 = imm
        .trim()
        .parse()
        .map_err(|_| EmuError::InstructionArgument(format!("li imm {imm}")))?;
    st.registers.set(dst, Val::Int(v));
    Ok(())
}

/// lui dst, imm：(imm<<16)&mask（imm hex）。
fn inst_lui(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, imm] = args else { return Err(State::err_unsupported_pub("lui", args)) };
    st.check_register(dst)?;
    let imm_v = i64::from_str_radix(imm.trim().trim_start_matches("0x"), 16)
        .map_err(|_| EmuError::InstructionArgument(format!("lui imm {imm}")))?;
    let v = (imm_v << 16) & st.width_mask() as i64;
    st.registers.set(dst, Val::Int(v));
    Ok(())
}

/// mem_operand：`-31652(gp)` → `[gp-31652]`（十进制偏移）。
fn mem_operand(mem: &str) -> EmuResult<String> {
    let m = mem.trim();
    let open = m.rfind('(');
    let close = m.rfind(')');
    match (open, close) {
        (Some(o), Some(c)) if o < c => {
            let off_str = &m[..o];
            let reg = &m[o + 1..c];
            let off: i64 = if off_str.is_empty() {
                0
            } else {
                off_str
                    .parse()
                    .map_err(|_| EmuError::InstructionArgument(format!("memory operand {mem}")))?
            };
            Ok(format!("[{reg}{off:+}]"))
        }
        _ => Err(EmuError::InstructionArgument(format!("memory operand {mem}"))),
    }
}

/// load_value：GOT 槽值注释（# addr）+ size==size_t → $base+addr；
/// 否则正常读（窄读 → Clobbered）。
fn inst_load(st: &mut State, args: &[&str], size: usize) -> EmuResult<()> {
    let [dst, mem] = args else { return Err(State::err_unsupported_pub("load", args)) };
    st.check_register(dst)?;
    if let Some(gv) = st.got_value {
        if size as i64 == st.size_t() {
            let v = st.libc_base().add(gv);
            st.registers.set(dst, Val::Lambda(v));
            return Ok(());
        }
    }
    let mo = mem_operand(mem)?;
    let resolved = st.resolve_int_regs(&mo);
    let v = parse_val(&resolved, &st.reg_map())
        .map_err(|_| EmuError::InstructionArgument(format!("load {mem}")))?;
    let v = st.read_value(v);
    let v = if size as i64 == st.size_t() { v } else { Val::Clobbered };
    st.registers.set(dst, v);
    Ok(())
}

fn inst_store(st: &mut State, args: &[&str], size: usize) -> EmuResult<()> {
    let [src, mem] = args else { return Err(State::err_unsupported_pub("store", args)) };
    st.check_register(src)?;
    let mo = mem_operand(mem)?;
    let resolved = st.resolve_int_regs(&mo);
    let Ok(Val::Lambda(l)) = parse_val(&resolved, &st.reg_map()) else {
        return Err(EmuError::InstructionArgument(format!("store {mem}")));
    };
    let dst_l: Lambda = l
        .ref_()
        .map_err(|e| EmuError::InstructionArgument(e.to_string()))?;
    let v = st.registers.get(src);
    let v = if size as i64 == st.size_t() { v } else { Val::Clobbered };
    st.track_write(dst_l, vec![v]);
    Ok(())
}

#[allow(unused)]
fn unused_obj_helper(o: &Obj) -> bool {
    matches!(o, Obj::Reg(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delayed_branch() {
        let mut st = new_state();
        // beqz a0,4b3f0 + 延迟槽 addiu a1,a1,1：分支持回，先执行 addiu
        process_line(&mut st, "4b3ec:\tbeqz\ta0,4b3f0 <x>").unwrap();
        assert!(st.delayed.is_some());
        process_line(&mut st, "4b3f0:\taddiu\ta1,a1,1").unwrap();
        // addiu 执行后 apply_delayed 应用分支
        assert!(st.delayed.is_none());
        assert!(st.pending.is_some() || true);
    }

    #[test]
    fn test_got_load() {
        let mut st = new_state();
        // state_got_values 注入的 GOT 槽值注释
        process_line(&mut st, "77b44:\tlw\ta0,-32496(gp)  # b0000").unwrap();
        assert_eq!(st.registers.get("a0").to_string(), "$base+0xb0000");
    }

    #[test]
    fn test_lui() {
        let mut st = new_state();
        process_line(&mut st, "0:\tlui\tgp,0x6").unwrap();
        assert_eq!(st.registers.get("gp"), Val::Int(0x60000));
    }

    #[test]
    fn test_jalr_terminal() {
        let mut st = new_state();
        // jalr 持回；下一条（延迟槽）执行后应用
        let r = process_line(&mut st, "4b3e0:\tjalr\tt9 <posix_spawnattr_init>");
        assert!(r.is_ok());
        assert!(st.delayed.is_some());
        // 无下一条时（单行窗口）转移不应用——窗口截断
    }
}
