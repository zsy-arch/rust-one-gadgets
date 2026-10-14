//! ArgumentResolution（master fetchers/argument_resolution.rb）→ Rust。
//!
//! 读模拟器终端状态，产出 (constraints, effect)；不可描述 → Err。

use crate::elf::Libc;
use crate::emulator21::processor::State;
use crate::emulator21::{Lambda, Val};

/// trivial_relation（master base.rb）：单边关系自判。
/// Some(true)=恒真 Some(false)=恒假 None=真约束。
pub fn trivial_relation(con: &str) -> Option<bool> {
    if con.contains(" || ") {
        return None;
    }
    // \A(?:\([su]\d+\))?(.+?) (op) (.+)\z
    let body = con.strip_prefix("(u32)").or_else(|| con.strip_prefix("(u64)"))
        .or_else(|| con.strip_prefix("(s32)")).or_else(|| con.strip_prefix("(s16)"))
        .or_else(|| con.strip_prefix("(s64)")).or_else(|| con.strip_prefix("(s8)"))
        .unwrap_or(con);
    let (lhs, op, rhs) = split_relation(body)?;
    let (l, r) = comparable_values(lhs, rhs)?;
    let v = match op {
        "==" => l == r,
        "!=" => l != r,
        "<=" => l <= r,
        ">=" => l >= r,
        "<" => l < r,
        ">" => l > r,
        _ => return None,
    };
    Some(v)
}

fn split_relation(body: &str) -> Option<(&str, &str, &str)> {
    for op in ["!=", "==", "<=", ">=", "<", ">"] {
        if let Some(i) = body.find(&format!(" {op} ")) {
            let (l, rest) = body.split_at(i);
            let r = &rest[2 + op.len()..];
            return Some((l.trim(), op, r.trim()));
        }
    }
    None
}

/// comparable_values：两侧均可数值化（同 obj 的裸偏移）才可比较。
fn comparable_values(lhs: &str, rhs: &str) -> Option<(i64, i64)> {
    if lhs == rhs {
        return Some((0, 0));
    }
    let left = parse_simple_lambda(lhs)?;
    let right = parse_simple_lambda(rhs)?;
    match (left, right) {
        (SimpleVal::Int(l), SimpleVal::Int(r)) => Some((l, r)),
        (SimpleVal::Offset(o1), SimpleVal::Offset(o2)) if o1.0 == o2.0 => Some((o1.1, o2.1)),
        _ => None,
    }
}

enum SimpleVal {
    Int(i64),
    Offset((String, i64)),
}

/// 裸值：整数 / `obj±imm`（无 deref、无运算）。cast 前缀已剥。
fn parse_simple_lambda(s: &str) -> Option<SimpleVal> {
    let s = s.trim();
    if let Some(v) = crate::lambda::parse_int_str(s) {
        return Some(SimpleVal::Int(v));
    }
    // obj[+-]0ximm
    let (base, off) = if let Some(i) = s.rfind("+0x") {
        let o = crate::lambda::parse_int_str(&s[i + 1..])?;
        (&s[..i], o)
    } else if let Some(i) = s.rfind("-0x") {
        let o = crate::lambda::parse_int_str(&s[i + 1..])?;
        (&s[..i], -o)
    } else {
        (s, 0)
    };
    if base.is_empty() || base.contains('[') || base.contains('(') {
        return None;
    }
    Some(SimpleVal::Offset((base.to_string(), off)))
}

/// resolve：按 pc 里的 call 目标分派。
pub fn resolve(st: &mut State, libc: &Libc) -> Result<(Vec<String>, String), ()> {
    let call = st.registers.get(&st.pc.clone()).to_string();
    if call.contains("posix_spawn") {
        return resolve_posix_spawn(st, libc);
    }
    if call.contains("execve") {
        return resolve_execve(st, libc);
    }
    if call.contains("execl") {
        return resolve_execl(st, libc);
    }
    Err(())
}

/// resolve 最终化（master resolve_suffix 尾部）：矛盾丢弃、恒真剔除。
pub fn finalize(cons: Vec<String>) -> Option<Vec<String>> {
    if cons.iter().any(|c| trivial_relation(c) == Some(false)) {
        return None;
    }
    Some(cons.into_iter().filter(|c| trivial_relation(c) != Some(true)).collect())
}

fn resolve_execve(st: &mut State, libc: &Libc) -> Result<(Vec<String>, String), ()> {
    let arg0 = st.argument(0);
    let arg1 = st.argument(1);
    let arg2 = st.argument(2);
    let (constraints, envp) = resolve_execve_args(st, libc, &arg0, &arg1, &arg2, true)?;
    let effect = format!("execve(\"/bin/sh\", {arg1}, {envp})");
    Ok((constraints, effect))
}

/// resolve_execve_args：arg0 须 /bin/sh；argv/envp 约束生成。
fn resolve_execve_args(
    st: &mut State,
    libc: &Libc,
    arg0: &Val,
    arg1: &Val,
    arg2: &Val,
    allow_null_argv: bool,
) -> Result<(Vec<String>, String), ()> {
    if !str_bin_sh(st, libc, &arg0.to_string()) {
        return Err(());
    }
    let mut cons = st.constraints();
    if let Some(con) = check_argv(st, libc, arg1, allow_null_argv) {
        if con == "\0DROP\0" {
            return Err(());
        }
        cons.push(con);
    }
    let mut envp = "environ".to_string();
    let ok = check_envp(st, libc, arg2, &mut |c: String| {
        cons.push(c);
        envp = arg2.to_string();
    });
    if !ok {
        return Err(());
    }
    Ok((cons, envp))
}

/// check_argv：返回 Some(constraint) / None（已有效）/ Some("\0DROP\0")（丢弃 gadget）。
fn check_argv(st: &State, libc: &Libc, argv_ptr: &Val, allow_null: bool) -> Option<String> {
    let argv_ptr = resolve_stack_deref(st, argv_ptr);
    if let Some(stack) = resolvable_stack(st, &argv_ptr) {
        return check_stack_argv(st, libc, &argv_ptr, stack, allow_null);
    }
    Some(check_nonstack_argv(&argv_ptr, allow_null))
}

/// resolvable_stack：deref0 的栈寄存器指针，或 element 0 已跟踪。
fn resolvable_stack(st: &State, lmda: &Val) -> Option<()> {
    let Val::Lambda(l) = lmda else { return None };
    if l.deref_count == 0 && crate::abi::is_stack_register(l.obj_str().as_str()) {
        let (_, _) = st.resolve_address(l);
        return Some(());
    }
    // element 0 是否已写
    let (stack_base, offset) = st.resolve_address(l);
    let base = stack_base?;
    let stack = st.stack_of(&base)?;
    if stack.contains_key(&offset) {
        Some(())
    } else {
        None
    }
}

fn check_stack_argv(
    st: &State,
    libc: &Libc,
    argv_ptr: &Val,
    _stack: (),
    allow_null: bool,
) -> Option<String> {
    let Val::Lambda(l) = argv_ptr else {
        return Some(check_nonstack_argv(argv_ptr, allow_null));
    };
    let (Some(base), offset) = st.resolve_address(l) else {
        return Some(check_nonstack_argv(argv_ptr, allow_null));
    };
    // master：tracked_stack 是 defaulting hash（寄存器 base 永远有栈），未写槽渲染 [base+off]
    let sz = st.size_t();
    let argv: Vec<String> = (0..4)
        .map(|i| {
            st.stack_of(&base)
                .and_then(|stack| stack.get(&(offset + sz * i)))
                .map(|v| v.to_string())
                .unwrap_or_else(|| {
                    let slot = Lambda::reg(&base).add(offset + sz * i).deref();
                    slot.to_string()
                })
        })
        .collect();

    // noexec 检查（bash -n 等）
    if let Some(opt) = global_str_content(libc, &argv[1]) {
        if opt.starts_with('-') && opt.contains('n') && opt.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Some("\0DROP\0".into());
        }
    }

    if argv[0] == "0" || (global_var(libc, &argv[0]) && argv[1] == "0") {
        return None; // already valid
    }
    if global_var(libc, &argv[0]) {
        return Some(generate_argv_with_sh(libc, &argv));
    }
    Some(generate_argv_without_sh(libc, argv_ptr, &argv, allow_null))
}

/// 全局变量判定（fetcher 侧：$base 相对形式）。
fn global_var(libc: &Libc, s: &str) -> bool {
    let _ = libc;
    base_relative(s)
}

fn base_relative(s: &str) -> bool {
    // \A\[*\$base(?:[+-]0x[0-9a-f]+)?\]*\z
    let s = s.trim();
    let s = s.trim_start_matches('[');
    let s = s.trim_end_matches(']');
    if s == "$base" {
        return true;
    }
    let Some(rest) = s.strip_prefix("$base") else { return false };
    rest.starts_with("+0x") || rest.starts_with("-0x")
}

/// 全局字符串内容（1..=16 可打印）。
fn global_str_content(libc: &Libc, element: &str) -> Option<String> {
    let off = string_file_offset(element)?;
    let bytes = &libc.data;
    if off < 1 || off as usize >= bytes.len() {
        return None;
    }
    let end = bytes[off as usize..].iter().position(|&b| b == 0)? + off as usize;
    let s = &bytes[off as usize..end];
    (1..=16).contains(&s.len()).then(|| s.iter().all(|&b| (0x20..=0x7e).contains(&b))).filter(|&x| x)
        .map(|_| String::from_utf8_lossy(s).to_string())
}

fn string_file_offset(element: &str) -> Option<u64> {
    let rest = element.strip_prefix("$base+")?;
    let hex = rest.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

fn generate_argv_with_sh(libc: &Libc, argv: &[String]) -> String {
    if argv[2] == "0" && !global_var(libc, &argv[1]) {
        return format!("{} == NULL || {{\"/bin/sh\", {}, NULL}} is a valid argv", argv[1], argv[1]);
    }
    let argv_gte3 = if argv[3] == "0" { "NULL".to_string() } else { format!("{}, ...", argv[3]) };
    if global_var(libc, &argv[1]) {
        format!(
            "{{\"sh\", {}, {}, {}}} is a valid argv",
            resolve_argv_element(libc, &argv[1]),
            resolve_argv_element(libc, &argv[2]),
            argv_gte3
        )
    } else {
        format!("{} == NULL || {{\"sh\", {}, {}, {}}} is a valid argv", argv[1], argv[1], argv[2], argv_gte3)
    }
}

fn generate_argv_without_sh(libc: &Libc, argv_ptr: &Val, argv: &[String], allow_null: bool) -> String {
    let mut cons = format!("{{{}}}", argv[0]);
    // 注意：master 形如 `{argv[0]`（开括号不闭合），NULL 收尾；这里 cons 先建 `{a, b, ...}` 主体
    cons.pop(); // 去掉尾随 `}`，后续元素追加后再统一收尾
    for a in argv[1..].iter() {
        if a == "0" {
            cons += ", NULL";
            break;
        }
        if global_var(libc, a) {
            cons += &format!(", {}", resolve_argv_element(libc, a));
        } else {
            cons += &format!(", {a}");
        }
    }
    if !cons.ends_with("NULL") {
        cons += ", ...";
    }
    cons += "} is a valid argv";
    let all_stack = argv.iter().all(|a| crate::abi::is_stack_register(a));
    if allow_null && all_stack {
        format!("{argv_ptr} == NULL || {} == NULL || {cons}", argv[0])
    } else {
        format!("{} == NULL || {cons}", argv[0])
    }
}

fn check_nonstack_argv(argv_ptr: &Val, allow_null: bool) -> String {
    if allow_null {
        format!("[{argv_ptr}] == NULL || {argv_ptr} == NULL || {argv_ptr} is a valid argv")
    } else {
        format!("[{argv_ptr}] == NULL || {argv_ptr} is a valid argv")
    }
}

/// resolve_stack_deref：单 deref 栈槽 → 跟踪值。
fn resolve_stack_deref(st: &State, ptr: &Val) -> Val {
    let Val::Lambda(l) = ptr else { return ptr.clone() };
    if l.deref_count != 1 || !crate::abi::is_stack_register(l.obj_str().as_str()) {
        return ptr.clone();
    }
    let Ok(peeled) = l.clone().ref_() else { return ptr.clone() };
    let (Some(base), offset) = st.resolve_address(&peeled) else { return ptr.clone() };
    let Some(stack) = st.stack_of(&base) else { return ptr.clone() };
    match stack.get(&offset) {
        Some(Val::Lambda(t)) if t.deref_count == 0 => Val::Lambda(t.clone()),
        _ => ptr.clone(),
    }
}

/// check_envp：全局 envp 判定 + 约束生成；返回 false 丢弃。
fn check_envp(st: &mut State, libc: &Libc, envp_ptr: &Val, emit: &mut dyn FnMut(String)) -> bool {
    if let Val::Lambda(l) = envp_ptr {
        if l.deref_count >= 2 {
            return global_var(libc, &envp_ptr.to_string());
        }
        if l.deref_count == 1 && environ_str(&envp_ptr.to_string()) {
            return true;
        }
    }
    let envp_ptr = resolve_stack_deref(st, envp_ptr);
    let mut cons: Option<String> = None;
    if let Val::Lambda(l) = &envp_ptr {
        if l.deref_count == 0 && resolvable_stack(st, &envp_ptr).is_some() {
            if let (Some(base), _offset) = st.resolve_address(l) {
                if let Some(stack) = st.stack_of(&base) {
                    let sz = st.size_t();
                    let envp: Vec<String> = (0..4)
                        .map(|i| {
                            stack.get(&(l.imm + sz * i)).map(|v| v.to_string()).unwrap_or_else(|| {
                                Lambda::reg(&base).add(l.imm + sz * i).deref().to_string()
                            })
                        })
                        .collect();
                    cons = if global_var(libc, &envp[0]) {
                        None
                    } else {
                        Some(format!("{envp_ptr} == NULL || {{{}, ...}} is a valid envp", envp.join(", ")))
                    };
                }
            }
        }
    }
    let cons = cons.unwrap_or_else(|| {
        format!("[{envp_ptr}] == NULL || {envp_ptr} == NULL || {envp_ptr} is a valid envp")
    });
    // writes_through 的附加约束
    for value in st.writes_through(&envp_ptr.to_string()) {
        emit(format!("{value} == NULL || readable: {value}"));
    }
    emit(cons);
    true
}

/// environ 符号判定（_*environ）。
fn environ_str(s: &str) -> bool {
    // aarch64：pc 相对 → $base+offset；无法直判符号名，保守 false
    //（master 的 environ? 由符号注释决定；textgen symbolize 提供时再启用）
    let _ = s;
    false
}

fn resolve_execl(st: &mut State, libc: &Libc) -> Result<(Vec<String>, String), ()> {
    if !str_bin_sh(st, libc, &st.argument(0).to_string()) {
        return Err(());
    }
    let mut args: Vec<String> = Vec::new();
    let mut arg = st.argument(1).to_string();
    if str_sh(libc, &arg) {
        arg = st.argument(2).to_string();
        args.push("\"sh\"".to_string());
    }
    if global_var(libc, &arg) {
        return Err(());
    }
    args.push(arg.clone());
    let mut cons = st.constraints();
    cons.push(format!("{arg} == NULL"));
    let effect = format!("execl(\"/bin/sh\", {})", args.join(", "));
    Ok((cons, effect))
}

fn resolve_posix_spawn(st: &mut State, libc: &Libc) -> Result<(Vec<String>, String), ()> {
    let args: Vec<Val> = (0..6).map(|i| st.argument(i)).collect();
    for i in [0, 2, 3] {
        if let Val::Int(v) = &args[i] {
            if *v != 0 {
                return Err(());
            }
        }
    }
    let (mut cons, envp) = resolve_execve_args(st, libc, &args[1], &args[4], &args[5], false)?;
    let arg0 = &args[0];
    let arg0s = arg0.to_string();
    if arg0s != "0" {
        if let Val::Lambda(l) = arg0 {
            if l.deref_count == 0 && l.obj_str().contains(&st.sp) {
                // 栈可写：免约束
            } else {
                cons.push(format!("{arg0} == NULL || writable: {arg0}"));
            }
        } else {
            return Err(());
        }
    }
    let arg2 = &args[2];
    let arg2s = arg2.to_string();
    if arg2s != "0" {
        let Val::Lambda(l) = arg2 else { return Err(()) };
        let d4 = Val::Lambda(l.clone().add(4).deref());
        cons.push(format!("{arg2} == NULL || (s32){d4} <= 0x0"));
    }
    let arg3 = &args[3];
    let arg3s = arg3.to_string();
    if arg3s != "0" {
        let Val::Lambda(l) = arg3 else { return Err(()) };
        let d0 = Val::Lambda(l.clone().deref());
        cons.push(format!("{arg3} == NULL || (u16){d0} == 0x0"));
    }
    let effect = format!(
        "posix_spawn({arg0}, \"/bin/sh\", {arg2}, {arg3}, {}, {envp})",
        args[4]
    );
    Ok((cons, effect))
}

/// str_bin_sh：$base 相对且偏移含 bin_sh hex。
fn str_bin_sh(st: &State, libc: &Libc, s: &str) -> bool {
    let _ = st;
    let Some(bin_sh) = libc.bin_sh_offset else { return false };
    s.contains("$base") && s.contains(&format!("{:x}", bin_sh))
}

fn str_sh(libc: &Libc, s: &str) -> bool {
    // sh_offset：\x00sh\x00 定位
    let idx = find_sh(libc);
    match idx {
        Some(off) => s.contains("$base") && s.contains(&format!("{:x}", off)),
        None => false,
    }
}

fn find_sh(libc: &Libc) -> Option<u64> {
    libc.data
        .windows(4)
        .position(|w| w == b"\x00sh\x00")
        .map(|i| i as u64 + 1)
}

fn resolve_argv_element(libc: &Libc, element: &str) -> String {
    match global_str_content(libc, element) {
        Some(content) => format!("{content:?}"),
        None => element.to_string(),
    }
}
