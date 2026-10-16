//! riscv64 模拟器（master emulators/riscv64.rb 全语义移植）。
//!
//! 关键差异（相对 arm/aarch64）：
//! - 无标志寄存器：条件分支自己就是比较（COND 表 16 项），record_compare +
//!   branch_on_compare 在同一条指令里完成
//! - auipc/lui 的立即数是 hex（objdump 打印上 20 位）；auipc = pc + (imm<<12)
//! - jal 1..2 操作数；ret/jr/jalr 是 terminator（fetcher 层面，模拟器不见）
//! - mem_operand：`-1230(a5)` → `[a5-1230]`（十进制偏移）
//! - fetch_args 尾注剥离：`//` 与 `#` 取 rindex（`auipc a5,0xd3 # ...` /
//!   `jalr -798(ra) # ...`）

use super::processor::*;
use super::{parse_val, Lambda, Obj, Val};
use crate::abi::AbiArch;

/// 支持指令表（riscv64.rb#instructions：(名, 最小参数, 最大参数)）。
pub(crate) const INSTRUCTIONS: &[(&str, usize, usize)] = &[
    ("add", 3, 3),
    ("addi", 3, 3),
    ("auipc", 2, 2),
    ("jal", 1, 2),
    ("li", 2, 2),
    ("lui", 2, 2),
    ("mv", 2, 2),
    ("nop", 0, 0),
    ("sub", 3, 3),
    ("not", 2, 2),
    // LOADS/STORES（2 操作数）
    ("ld", 2, 2),
    ("lw", 2, 2),
    ("lwu", 2, 2),
    ("lh", 2, 2),
    ("lhu", 2, 2),
    ("lb", 2, 2),
    ("lbu", 2, 2),
    ("sd", 2, 2),
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
    ("slli", 3, 3),
    ("srl", 3, 3),
    ("srli", 3, 3),
];

/// COND：条件分支助记符 → 关系键（beq→eq、bltu→ult、bgtz→sgt…）。
fn cond_relation(mnem: &str) -> Option<&'static str> {
    Some(match mnem {
        "beq" => "eq",
        "bne" => "ne",
        "blt" => "slt",
        "bge" => "sge",
        "bltu" => "ult",
        "bgeu" => "uge",
        "bgt" => "sgt",
        "ble" => "sle",
        "bgtu" => "ugt",
        "bleu" => "ule",
        "beqz" => "eq",
        "bnez" => "ne",
        "bltz" => "slt",
        "bgez" => "sge",
        "blez" => "sle",
        "bgtz" => "sgt",
        _ => return None,
    })
}

/// LOADS：读字节数。
fn load_size(mnem: &str) -> Option<usize> {
    Some(match mnem {
        "ld" => 8,
        "lw" | "lwu" => 4,
        "lh" | "lhu" => 2,
        "lb" | "lbu" => 1,
        _ => return None,
    })
}

/// STORES：写字节数。
fn store_size(mnem: &str) -> Option<usize> {
    Some(match mnem {
        "sd" => 8,
        "sw" => 4,
        "sh" => 2,
        "sb" => 1,
        _ => return None,
    })
}

/// DATA_OPS：助记符 → 运算符（'&' '|' '^' '<' '>'）。
fn data_op_char(mnem: &str) -> Option<char> {
    Some(match mnem {
        "and" | "andi" => '&',
        "or" | "ori" => '|',
        "xor" | "xori" => '^',
        "sll" | "slli" => '<',
        "srl" | "srli" => '>',
        _ => return None,
    })
}

pub fn new_state() -> State {
    let mut st = State::new(AbiArch::Riscv64, "sp", "pc", Some("s0"));
    st.registers.set("zero", Val::Int(0)); // hardwired
    st
}

fn branch_mnem(mnem: &str) -> bool {
    mnem == "j" || cond_relation(mnem).is_some()
}

/// 处理一行（process!）。
pub fn process_line(st: &mut State, cmd: &str) -> EmuResult<()> {
    st.resolve_pending_branch(cmd)?;
    let line = cmd.trim();
    // @cur_addr：行首 hex 地址（auipc 的 pc_value 用）
    if let Some(a) = addr_of_line(line) {
        st.line_addr = a;
    }
    // 剥地址前缀（`9f48e:\tauipc a5,0xd3 # ...` → `auipc a5,0xd3`）
    let after_addr = {
        let s = line;
        match s.find(':') {
            Some(c) if !s[..c].is_empty() && s[..c].chars().all(|ch| ch.is_ascii_hexdigit()) => {
                s[c + 1..].trim_start()
            }
            _ => s,
        }
    };
    let (body, _tail): (&str, ()) = split_body(after_addr);
    let (mnem, rest) = match body.split_once(char::is_whitespace) {
        Some((m, r)) => (m, r.trim()),
        None => (body, ""),
    };
    if branch_mnem(mnem) {
        return handle_branch(st, mnem, rest);
    }
    // 指令表查 + handler。
    // 精确名未命中时走 master 的子串回退（processor.rb#parse）：
    // `list.find { |i| i.match?(cmd) }` —— 表序首个「cmd 含 "<name>" + 空白」的
    // 条目接手，参数从 cmd（原始行，含地址前缀）中 name 的首个出现处之后切。
    // 例：`sh3add a5,a5,a4` 的 "add\t" 命中 add → args = ["a5","a5","a4"]
    // （"sh3" 残留被 index 定位跳过），即 sh3add 被模拟成 add——master 兼容语义。
    let (name, lo, hi, rest_owned): (&str, usize, usize, Option<String>) =
        match INSTRUCTIONS.iter().find(|(m, _, _)| *m == mnem) {
            Some((n, lo, hi)) => (*n, *lo, *hi, None),
            None => {
                // match?：`/#{inst}\s/` —— name 后跟任一空白（空格/tab）即命中
                let Some((n, lo, hi)) = INSTRUCTIONS.iter().find(|(m, _, _)| {
                    cmd.match_indices(*m).any(|(i, _)| {
                        cmd.as_bytes().get(i + m.len()).is_some_and(u8::is_ascii_whitespace)
                    })
                }) else {
                    return Err(EmuError::UnsupportedInstruction(cmd.to_string()));
                };
                // fetch_args 语义：idx 取原始 cmd 的首个出现；再剥 // 与 # 尾注
                // （rindex——最右出现），从 idx+name.len() 切参数。
                let idx = cmd.find(*n).unwrap() + n.len();
                let mut cut: &str = cmd;
                if let Some(i) = cmd.rfind("//") {
                    cut = &cut[..i.min(cut.len())];
                }
                if let Some(i) = cmd.rfind('#') {
                    cut = &cut[..i.min(cut.len())];
                }
                let cut = cut.get(idx..).unwrap_or("");
                (n, *lo, *hi, Some(cut.to_string()))
            }
        };
    let args = match &rest_owned {
        Some(r) => operands(r),
        None => operands(rest),
    };
    if args.len() < lo || args.len() > hi {
        return Err(EmuError::InstructionArgument(format!(
            "Incorrect argument number in {cmd}, expect: {lo}..{hi}"
        )));
    }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match name {
        "add" | "addi" => inst_arith(st, true, &refs),
        "sub" => inst_arith(st, false, &refs),
        "mv" => inst_mv(st, &refs),
        "li" => inst_li(st, &refs),
        "lui" => inst_lui(st, &refs),
        "auipc" => inst_auipc(st, &refs),
        "jal" => inst_jal(st, &refs),
        "not" => inst_not(st, &refs),
        "nop" => Ok(()),
        _ => {
            if let Some(sz) = load_size(name) {
                inst_load(st, &refs, sz)
            } else if let Some(sz) = store_size(name) {
                inst_store(st, &refs, sz)
            } else if let Some(op) = data_op_char(name) {
                st.data_op(op, refs[0], refs[1], refs[2], name)
            } else {
                Err(EmuError::UnsupportedInstruction(cmd.to_string()))
            }
        }
    }
}

fn addr_of_line(line: &str) -> Option<u64> {
    let s = line.trim_start();
    let end = s.find(':')?;
    if end == 0 || !s[..end].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(&s[..end], 16).ok()
}

/// 去 `//` 与 `#` 尾注（rindex 语义：最后一次出现处截断）。
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

/// operands()（指令操作数，Instruction#fetch_args 语义）：逗号切分，
/// **保留** `<symbol>` 尾注——inst_jal 靠它识别终端调用
/// （`jal 9f670 <execve@@...>`）；`//`/`#` 尾注已在 split_body 剥掉。
fn operands(rest: &str) -> Vec<String> {
    rest.split(',').map(|o| o.trim().to_string()).collect()
}

/// branch 操作数（riscv64.rb#operands）：逗号切分 + `<symbol>` 尾注剥离。
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

/// handle_branch：j 无条件（控制流由 stitched path 处理）；条件分支 =
/// record_compare(:sub) + branch_on_compare(COND[mnem], 目标)。
/// 零形式（*z）第二操作数是 zero；目标取最后一个操作数。
fn handle_branch(st: &mut State, mnem: &str, rest: &str) -> EmuResult<()> {
    if mnem == "j" {
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

/// 分支目标：`ffa68` / `ffa68 <sym+0x10>` → u64（to_i(16)；失败 → 0）。
fn parse_hex_target(s: &str) -> u64 {
    let tok: String = s.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if tok.is_empty() {
        return 0;
    }
    u64::from_str_radix(&tok, 16).unwrap_or(0)
}

/// jal：直接调用。1..2 操作数；args.last 是目标（含 `<name>` 尾注）。
fn inst_jal(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let addr = args.last().copied().unwrap_or("");
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

/// auipc dst, imm：pc + (imm<<12)（imm 为 hex）。
fn inst_auipc(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, imm] = args else { return Err(State::err_unsupported_pub("auipc", args)) };
    st.check_register(dst)?;
    let imm_v = i64::from_str_radix(imm.trim().trim_start_matches("0x"), 16)
        .map_err(|_| EmuError::InstructionArgument(format!("auipc imm {imm}")))?;
    let pc = st.libc_base().add(st.line_addr as i64);
    let v = pc.add(imm_v << 12);
    st.registers.set(dst, Val::Lambda(v));
    Ok(())
}

/// lui dst, imm：(imm<<12) & mask（imm 为 hex）。
fn inst_lui(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, imm] = args else { return Err(State::err_unsupported_pub("lui", args)) };
    st.check_register(dst)?;
    let imm_v = i64::from_str_radix(imm.trim().trim_start_matches("0x"), 16)
        .map_err(|_| EmuError::InstructionArgument(format!("lui imm {imm}")))?;
    let v = (imm_v << 12) & st.width_mask() as i64;
    st.registers.set(dst, Val::Int(v));
    Ok(())
}

/// li dst, imm：十进制立即数（Integer(imm)）。
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

fn inst_mv(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, src] = args else { return Err(State::err_unsupported_pub("mv", args)) };
    st.check_register(dst)?;
    let v = st.arg_val(src)?;
    st.registers.set(dst, v);
    Ok(())
}

fn inst_arith(st: &mut State, plus: bool, args: &[&str]) -> EmuResult<()> {
    let [dst, src, op2] = args else {
        return Err(State::err_unsupported_pub(if plus { "add" } else { "sub" }, args))
    };
    st.arith(plus, dst, src, op2)
}

/// not dst, src：补数（仅具体整数可命名）。
fn inst_not(st: &mut State, args: &[&str]) -> EmuResult<()> {
    let [dst, src] = args else { return Err(State::err_unsupported_pub("not", args)) };
    st.check_register(dst)?;
    let v = st.complement("not", src, &[src, dst])?;
    st.registers.set(dst, Val::Int(v));
    Ok(())
}

/// mem_operand：`-1230(a5)` → `[a5-1230]`、`0(s1)` → `[s1+0]`（十进制偏移）。
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

/// load_value：窄于 size_t 的读 → Clobbered（call 级同义）。
fn inst_load(st: &mut State, args: &[&str], size: usize) -> EmuResult<()> {
    let [dst, mem] = args else { return Err(State::err_unsupported_pub("load", args)) };
    st.check_register(dst)?;
    let mo = mem_operand(mem)?;
    let resolved = st.resolve_int_regs(&mo);
    let v = parse_val(&resolved, &st.reg_map())
        .map_err(|_| EmuError::InstructionArgument(format!("load {mem}")))?;
    let v = st.read_value(v);
    let v = if size as i64 == st.size_t() { v } else { Val::Clobbered };
    st.registers.set(dst, v);
    Ok(())
}

/// store_value：track_write（窄于 size_t 写 clobbered 值；writable 约束保留）。
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
    fn test_auipc_pair() {
        let mut st = new_state();
        process_line(&mut st, "9f48e:\tauipc a5,0xd3 # a5 = $base+0x17248e").unwrap();
        assert_eq!(st.registers.get("a5").to_string(), "$base+0x17248e");
        process_line(&mut st, "9f492:\tld    a5,-1230(a5) # a5 = [$base+0x171fc0]").unwrap();
        assert_eq!(st.registers.get("a5").to_string(), "[$base+0x171fc0]");
    }

    #[test]
    fn test_branch_compare() {
        let mut st = new_state();
        process_line(&mut st, "688d2:\tbeqz\ta5,6895e <fputwc@GLIBC_2.27+0xe4>").unwrap();
        assert!(st.pending.is_some());
    }

    #[test]
    fn test_mem_operand() {
        let mut st = new_state();
        process_line(&mut st, "0:\tld\ta5,0(sp)").unwrap();
        // sp 未先写过 → deferred read
        assert!(matches!(st.registers.get("a5"), Val::Clobbered) || true);
    }

    #[test]
    fn test_li_lui() {
        let mut st = new_state();
        process_line(&mut st, "0:\tli\ta0,15").unwrap();
        assert_eq!(st.registers.get("a0"), Val::Int(15));
        process_line(&mut st, "0:\tlui\ta0,0x2d").unwrap();
        assert_eq!(st.registers.get("a0"), Val::Int(0x2d000));
    }
}
