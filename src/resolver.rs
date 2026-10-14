//! 参数解析：模拟到终点 call 后，把寄存器状态翻译成 gadget 约束。
//! 对齐 one_gadget **v1.10.0** `Fetchers::Base#resolve` 系（base.rb 79-256 行）。

use crate::emulator::{Constraint, Emulator};
use crate::lambda::{Lambda, Val};

/// resolve 的产物。
pub struct Resolution {
    pub constraints: Vec<String>,
    pub effect: String,
}

/// 一次 resolve 的上下文（i386 的 GOT 基寄存器等）。
struct Ctx {
    arch: crate::elf::Arch,
    /// i386：rel_sh 的 hex 文本（不含 0x）。
    rel_sh_hex: String,
    /// i386：(rel_sh − 5) 的 hex 文本（execl 的 "sh" 判定）。
    rel_sh_m5_hex: String,
    /// i386：arg0 剥 deref 后的基（`esi` / `ecx` / `[ebp-0x2c]` 等）。
    base_reg: Option<String>,
}

/// 主入口：按 terminal call 类型分派。
pub fn resolve(p: &Emulator, libc: &crate::elf::Libc) -> Option<Resolution> {
    let call = p.terminal_call.as_ref()?.to_string();
    // 先构造上下文：i386 需要 rel_sh + 从 arg0 提取 GOT 基寄存器
    let ctx = match libc.arch {
        crate::elf::Arch::X64 => {
            Ctx { arch: libc.arch, rel_sh_hex: String::new(), rel_sh_m5_hex: String::new(), base_reg: None }
        }
        _ => {
            let rel_sh = libc.rel_sh()?;
            let arg0 = p.argument(0);
            // str_bin_sh?：arg0 文本含 rel_sh hex
            if !arg0.to_string().contains(&format!("{rel_sh:x}")) {
                return None;
            }
            // base_reg = arg0.deref.obj.to_s：基对象文本（寄存器名或嵌套值），
            // 不含 imm/deref（Ruby Lambda#deref 复制 obj/immi 后 +1 deref，再取 .obj）
            let Val::Lambda(l) = &arg0 else { return None };
            Ctx {
                arch: libc.arch,
                rel_sh_hex: format!("{rel_sh:x}"),
                rel_sh_m5_hex: format!("{:x}", rel_sh.saturating_sub(5)),
                base_reg: Some(l.obj_str()),
            }
        }
    };
    let res = if call.contains("posix_spawn") {
        resolve_posix_spawn(p, &ctx)
    } else if call.contains("execve") {
        resolve_execve(p, &ctx)
    } else if call.contains("execl") {
        // amd64 1.10.0 未实现 str_sh?（NotImplementedError）→ 丢弃；i386 可解
        if ctx.arch == crate::elf::Arch::X86 { resolve_execl(p, &ctx) } else { None }
    } else {
        return None;
    }?;
    // i386 后处理：unshift GOT 约束 + 删除 writable: base_reg
    if ctx.arch == crate::elf::Arch::X86 {
        let base = ctx.base_reg.clone().expect("i386 resolve sets base_reg");
        let mut cons = res.constraints;
        cons.retain(|c| !c.starts_with(&format!("writable: {base}")));
        cons.insert(0, format!("{base} is the GOT address of libc"));
        return Some(Resolution { constraints: cons, effect: res.effect });
    }
    Some(res)
}

/// v1.10.0 `constraints` 输出：writable 按 deref==0 归并基名，去重 + 字典序排序。
pub fn render_constraints(cons: &[Constraint]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for c in cons {
        let (key, _text) = match c {
            Constraint::Writable(l) => {
                let key = if l.deref_count == 0 {
                    // obj 名（基寄存器）
                    l.root_name_str().unwrap_or_default().to_string()
                } else {
                    l.to_string()
                };
                (key, format!("writable: {l}"))
            }
            Constraint::Raw(s) => (s.clone(), s.clone()),
        };
        if !seen_contains(&seen, &key) {
            seen.push(key);
            // text 也要按 key 语义去重：直接存 text，seen 存 key
        }
    }
    // 实际输出按 text 去重排序（key 仅用于 writable 归并分组）
    let mut out: Vec<String> = Vec::new();
    let mut used_keys: Vec<String> = Vec::new();
    for c in cons {
        let (key, text) = match c {
            Constraint::Writable(l) => {
                let key = if l.deref_count == 0 {
                    l.root_name_str().unwrap_or_default().to_string()
                } else {
                    l.to_string()
                };
                (key, format!("writable: {l}"))
            }
            Constraint::Raw(s) => (s.clone(), s.clone()),
        };
        if !used_keys.contains(&key) {
            used_keys.push(key);
            out.push(text);
        }
    }
    out.sort();
    out
}

fn seen_contains(seen: &[String], key: &str) -> bool {
    seen.iter().any(|s| s == key)
}

/// `str_bin_sh?`：amd64 = 含 `rip+0x`；i386 = 含 rel_sh hex。
fn str_bin_sh(s: &str, ctx: &Ctx) -> bool {
    match ctx.arch {
        crate::elf::Arch::X64 => s.contains("rip+0x"),
        _ => s.contains(&ctx.rel_sh_hex),
    }
}

/// `global_var?`：amd64 = 含 `rip`；i386 = 含 base_reg。
fn global_var(s: &str, ctx: &Ctx) -> bool {
    match ctx.arch {
        crate::elf::Arch::X64 => s.contains("rip"),
        _ => ctx.base_reg.as_ref().is_some_and(|b| s.contains(b.as_str())),
    }
}

fn resolve_execve(p: &Emulator, ctx: &Ctx) -> Option<Resolution> {
    let arg0 = p.argument(0).to_string();
    let arg1 = p.argument(1).to_string();
    let arg2 = p.argument(2).to_string();
    let (constraints, envp) = resolve_execve_args(p, &arg0, &arg1, &arg2, true, ctx)?;
    Some(Resolution {
        constraints,
        effect: format!("execve(\"/bin/sh\", {arg1}, {envp})"),
    })
}

/// execve 参数三元组解析；返回 (约束列表, envp 渲染)。None = 丢弃。
fn resolve_execve_args(
    p: &Emulator,
    arg0: &str,
    arg1: &str,
    arg2: &str,
    allow_null_argv: bool,
    ctx: &Ctx,
) -> Option<(Vec<String>, String)> {
    if !str_bin_sh(arg0, ctx) {
        return None;
    }
    let mut cons = render_constraints(&p.constraints_snapshot());
    if let Some(c) = check_argv(p, arg1, allow_null_argv, ctx) {
        cons.push(c);
    }
    let mut envp = "environ".to_string();
    let c = check_envp(p, arg2, ctx)?;
    if let Some(c) = c {
        cons.push(c);
        envp = arg2.to_string();
    }
    Some((cons, envp))
}

/// argv 约束生成。
fn check_argv(p: &Emulator, arg: &str, allow_null: bool, ctx: &Ctx) -> Option<String> {
    // lmda = Lambda.parse(arg)——**不带 predefined**（base.rb 125 行），imm 保持字面值
    let parsed = crate::lambda::parse_operand(arg, &std::collections::HashMap::new()).ok()?;
    if let Val::Lambda(l) = &parsed {
        if l.deref_count == 0 {
            if let Some(root) = l.root_name_str() {
                if crate::emulator::is_stack_register(root) {
                    return check_stack_argv(p, l, allow_null, ctx);
                }
            }
        }
    }
    Some(check_nonstack_argv(arg, allow_null))
}

/// sp/bp 栈上的 argv。
fn check_stack_argv(p: &Emulator, lmda: &Lambda, allow_null: bool, ctx: &Ctx) -> Option<String> {
    let stack = p.stack_of_root(lmda);
    let stride = p.size_t_of();
    let argv: Vec<String> = (0..4)
        .map(|i| stack.get_or(lmda.imm + stride * i))
        .collect();
    // 已有效：argv[0]=='0' 或 (全局 且 argv[1]=='0')
    if argv[0] == "0" || (global_var(&argv[0], ctx) && argv[1] == "0") {
        return None;
    }
    if global_var(&argv[0], ctx) {
        return Some(generate_argv_with_sh(&argv, ctx));
    }
    Some(generate_argv_without_sh(&lmda.to_string(), &argv, allow_null, ctx))
}

/// argv[0] 已是 libc 全局（"/bin/sh" 或 "sh"）。
fn generate_argv_with_sh(argv: &[String], ctx: &Ctx) -> String {
    if argv[2] == "0" && !global_var(&argv[1], ctx) {
        return format!("{} == NULL || {{\"/bin/sh\", {}, NULL}} is a valid argv", argv[1], argv[1]);
    }
    let argv_gte3 = if argv[3] == "0" { "NULL".to_string() } else { format!("{}, ...", argv[3]) };
    if global_var(&argv[1], ctx) {
        format!("{{\"sh\", \"-c\", {}, {}}} is a valid argv", argv[2], argv_gte3)
    } else {
        format!("{} == NULL || {{\"sh\", {}, {}, {}}} is a valid argv", argv[1], argv[1], argv[2], argv_gte3)
    }
}

fn generate_argv_without_sh(arg: &str, argv: &[String], allow_null: bool, ctx: &Ctx) -> String {
    let mut cons = format!("{{{}", argv[0]);
    for (i, a) in argv.iter().enumerate().skip(1) {
        if a == "0" {
            cons += ", NULL";
            break;
        } else if i == 1 && global_var(a, ctx) {
            // 1.10.0：仅 i==1 的全局变量渲染 "-c"（{"sh"→argv[0], "-c", ...} 语义）
            cons += ", \"-c\"";
        } else {
            cons += &format!(", {a}");
        }
    }
    if !cons.ends_with("NULL") {
        cons += ", ...";
    }
    cons += "} is a valid argv";
    if allow_null && argv.iter().all(|a| crate::emulator::is_stack_register(a)) {
        format!("{arg} == NULL || {} == NULL || {cons}", argv[0])
    } else {
        format!("{} == NULL || {cons}", argv[0])
    }
}

fn check_nonstack_argv(arg: &str, allow_null: bool) -> String {
    if allow_null {
        format!("[{arg}] == NULL || {arg} == NULL || {arg} is a valid argv")
    } else {
        format!("[{arg}] == NULL || {arg} is a valid argv")
    }
}

/// envp 约束；None = 丢弃。Some(None) = 无约束（environ 命中）。
fn check_envp(p: &Emulator, arg: &str, ctx: &Ctx) -> Option<Option<String>> {
    // [[ 开头且全局 → environ；[[ 开头非全局 → 丢弃
    if arg.starts_with("[[") {
        return if global_var(arg, ctx) { Some(None) } else { None };
    }
    // 同 check_argv：Ruby Lambda.parse(arg) 不带 predefined
    let parsed = crate::lambda::parse_operand(arg, &std::collections::HashMap::new()).ok()?;
    if let Val::Lambda(l) = &parsed {
        if l.deref_count == 0 {
            if let Some(root) = l.root_name_str() {
                if crate::emulator::is_stack_register(root) {
                    let stack = p.stack_of_root(l);
                    let stride = p.size_t_of();
                    let envp: Vec<String> = (0..4)
                        .map(|i| stack.get_or(l.imm + stride * i))
                        .collect();
                    let cons = if global_var(&envp[0], ctx) {
                        None
                    } else {
                        Some(format!("{arg} == NULL || {{{}, ...}} is a valid envp", envp.join(", ")))
                    };
                    return Some(cons);
                }
            }
        }
    }
    Some(Some(format!("[{arg}] == NULL || {arg} == NULL || {arg} is a valid envp")))
}

/// execl 解析（i386 专属——amd64 的 str_sh? 未实现即丢弃）。
fn resolve_execl(p: &Emulator, ctx: &Ctx) -> Option<Resolution> {
    if !str_bin_sh(&p.argument(0).to_string(), ctx) {
        return None;
    }
    let mut args: Vec<String> = Vec::new();
    let mut arg = p.argument(1).to_string();
    // str_sh?：含 (rel_sh − 5) hex → 实际是 "sh"，真实 argv 从 arg2 起
    if arg.contains(&ctx.rel_sh_m5_hex) {
        arg = p.argument(2).to_string();
        args.push("\"sh\"".to_string());
    }
    // base 相关约束不可满足 → 丢弃（global_var? 命中）
    if global_var(&arg, ctx) {
        return None;
    }
    args.push(arg.clone());
    let cons = render_constraints(&p.constraints_snapshot());
    let mut cons = cons;
    cons.push(format!("{arg} == NULL"));
    Some(Resolution {
        constraints: cons,
        effect: format!("execl(\"/bin/sh\", {})", args.join(", ")),
    })
}

/// posix_spawn 解析。
fn resolve_posix_spawn(p: &Emulator, ctx: &Ctx) -> Option<Resolution> {
    let args: Vec<String> = (0..6).map(|i| p.argument(i).to_string()).collect();
    let (mut cons, envp) = resolve_execve_args(p, &args[1], &args[4], &args[5], false, ctx)?;

    // pid（arg0）
    let arg0 = args[0].clone();
    if arg0 != "0" {
        // deref==0 且包含 sp → 栈可写，免约束
        let is_stack = crate::lambda::parse_operand(&arg0, &p.regs_snapshot())
            .ok()
            .and_then(|v| match v {
                Val::Lambda(l) if l.deref_count == 0 => {
                    Some(l.to_string().contains("rsp") || l.to_string().contains("esp"))
                }
                _ => None,
            })
            .unwrap_or(false);
        if !is_stack {
            cons.push(format!("{arg0} == NULL || writable: {arg0}"));
        }
    }
    // file_actions（arg2）
    let arg2 = args[2].clone();
    if arg2 != "0" {
        let l = crate::lambda::parse_operand(&arg2, &p.regs_snapshot()).ok()?;
        if let Val::Lambda(l) = l {
            cons.push(format!("{arg2} == NULL || (s32){} <= 0", l.add_imm(4).deref()));
        } else {
            return None;
        }
    }
    // attrp（arg3）
    let arg3 = args[3].clone();
    if arg3 != "0" {
        let l = crate::lambda::parse_operand(&arg3, &p.regs_snapshot()).ok()?;
        if let Val::Lambda(l) = l {
            cons.push(format!("{arg3} == NULL || (u16){} == NULL", l.deref()));
        } else {
            return None;
        }
    }

    Some(Resolution {
        constraints: cons,
        effect: format!(
            "posix_spawn({}, \"/bin/sh\", {}, {}, {}, {})",
            args[0], args[2], args[3], args[4], envp
        ),
    })
}
