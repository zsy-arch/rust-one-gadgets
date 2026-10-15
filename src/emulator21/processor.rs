//! 2.1.1 Processor 共享状态与生命周期（master processor.rb + register_file.rb）。
//!
//! 各 arch 的指令分发是自由函数（`aarch64::process_line(&mut State, cmd)`），
//! 由 `Emulator` enum 分发——避免 trait 对象双重借用。

use super::{parse_val, Lambda, Val};
use crate::abi::{self, AbiArch};
use std::collections::HashMap;

/// 模拟错误（Ruby Error 层级）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmuError {
    /// 指令不在支持表（refused_line 语义）。
    UnsupportedInstruction(String),
    /// 指令理解但参数形式不支持（中止候选，不记 refused）。
    UnsupportedInstructionArgument(String),
    /// 寄存器值是 clobbered（读作比较操作数时中止路径）。
    ClobberedRegister(String),
    /// 分支约束矛盾（路径不可行）。
    InfeasiblePath(String),
    /// 参数形式非法。
    InstructionArgument(String),
}

pub type EmuResult<T> = Result<T, EmuError>;

fn err_unsupported(inst: &str, args: &[&str]) -> EmuError {
    EmuError::UnsupportedInstructionArgument(format!("{} {}", inst, args.join(", ")))
}

/// 终端调用判定（TERMINAL_CALL_RE 全匹配语义）。
pub fn is_terminal_call(name: &str) -> bool {
    // posix_spawnp? | exec(ve|l|v)[a-z]*
    if name == "posix_spawn" || name == "posix_spawnp" {
        return true;
    }
    if let Some(rest) = name.strip_prefix("exec") {
        let mut chars = rest.chars();
        let ok = match chars.next() {
            Some('v') => matches!(chars.next(), Some('e') | Some('p') | None) || rest.len() >= 2,
            Some('l') => true,
            _ => false,
        };
        // 剩余字符须为 [a-z]*
        return ok && rest.chars().all(|c| c.is_ascii_lowercase());
    }
    false
}

// clang-format off
/// SafeCalls::COMMON：函数名（或前缀）→ 参数要求，先具体后泛化。
pub const SAFE_CALLS: &[(&str, &[(usize, PtrReq)])] = &[
    ("sigprocmask", &[(1, PtrReq::NullableDeref)]),
    ("__sigaction", &[(1, PtrReq::NullableDeref), (2, PtrReq::Null)]),
    ("__close", &[(0, PtrReq::ClosedFd)]),
    ("unsetenv", &[(0, PtrReq::GlobalVar)]),
    ("posix_spawnattr_setsigmask", &[(0, PtrReq::Writable), (1, PtrReq::Deref)]),
    ("posix_spawnattr_setsigdefault", &[(0, PtrReq::Writable), (1, PtrReq::Deref)]),
    ("posix_spawnattr_", &[(0, PtrReq::Writable)]),
];
// clang-format on

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtrReq {
    Writable,
    Deref,
    NullableDeref,
    Null,
    ClosedFd,
    GlobalVar,
}

/// 寄存器文件：窄名视图共享存储。
pub struct RegisterFile {
    full: HashMap<String, Val>,
    views: HashMap<String, String>,
    halves: HashMap<String, Val>,
}

impl RegisterFile {
    pub fn build(names: &[String], narrow: &[(String, String)]) -> Self {
        let views: HashMap<String, String> = narrow.iter().cloned().collect();
        let mut full_names: Vec<String> = names
            .iter()
            .map(|n| views.get(n).cloned().unwrap_or_else(|| n.clone()))
            .collect();
        full_names.sort();
        full_names.dedup();
        let mut full = HashMap::new();
        for n in &full_names {
            full.insert(n.clone(), Val::Lambda(Lambda::reg(n)));
        }
        RegisterFile { full, views, halves: HashMap::new() }
    }

    fn full_name<'t>(&'t self, name: &'t str) -> &'t str {
        match self.views.get(name) {
            Some(s) => s.as_str(),
            None => name,
        }
    }

    fn is_view(&self, name: &str) -> bool {
        self.views.contains_key(name)
    }

    pub fn get(&self, name: &str) -> Val {
        let full = self.full_name(name).to_string();
        let value = self.full.get(&full).cloned().unwrap_or(Val::Lambda(Lambda::reg(&full)));
        if self.is_view(name) {
            self.narrowed(name, value, &full)
        } else {
            value
        }
    }

    /// 窄名读：寄存器仍是 entry 值时返回窄名自身 lambda（master narrowed）。
    fn narrowed(&self, name: &str, value: Val, full: &str) -> Val {
        if let Val::Lambda(l) = &value {
            let is_entry = matches!(&l.obj, super::Obj::Reg(r) if r == full)
                && l.deref_count == 0
                && l.imm == 0
                && l.op.is_none();
            if is_entry {
                return self
                    .halves
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| Val::Lambda(Lambda::reg(name)));
            }
        }
        value
    }

    pub fn set(&mut self, name: &str, value: Val) {
        let full = self.full_name(name).to_string();
        self.full.insert(full, value);
    }

    pub fn contains(&self, name: &str) -> bool {
        self.full.contains_key(self.full_name(name))
    }
}

/// compare 的 ALU 操作（COMPARE_OPS）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Sub,
    Add,
    And,
}

impl CmpOp {
    pub fn ordered(self) -> bool {
        !matches!(self, CmpOp::And)
    }
}

/// 待解析分支（目标 + taken?→三元组）。
pub struct PendingBranch {
    pub target: u64,
    pub compare: Box<dyn FnOnce(bool) -> (String, String, String) + Send>,
}

/// 约束条目。
#[derive(Clone, Debug)]
pub enum CtItem {
    Writable(Lambda),
    Readable(Lambda),
    Cmp(String, String, String),
    Raw(String),
}

/// 共享模拟状态（一个候选窗口）。
pub struct State {
    pub arch: AbiArch,
    pub registers: RegisterFile,
    pub sp: String,
    pub pc: String,
    #[allow(dead_code)] // arm（r11 frame pointer）接入后使用
    #[allow(dead_code)] // arm（r11 frame pointer）接入后使用
    pub bp: Option<String>,
    pub refused_line: Option<String>,
    pub(crate) constraints: Vec<CtItem>,
    pub(crate) deferred_reads: Vec<(Val, bool)>,
    pub(crate) closed_fds: Vec<String>,
    pub(crate) flags: Option<(CmpOp, String, String)>,
    pub(crate) pending: Option<PendingBranch>,
    /// tracked memory：base 文本 → offset → 值。
    pub(crate) mem: HashMap<String, HashMap<i64, Val>>,
    /// 操作地址的写入（writes_through 用）。
    pub(crate) derived_writes: Vec<(Lambda, Vec<Val>)>,
    /// mips：窗口起始行地址（pc 语义；arm thumb 由 fetcher 注入）。
    #[allow(dead_code)] // mips/arm 切片接入后使用
    pub line_addr: u64,
    /// arm：当前窗口是否 thumb（value_of 的 pc 偏移）。
    pub thumb: bool,
    /// arm：track_mode 的上一行地址（2 字节步距证明 thumb）。
    pub(crate) prev_addr: u64,
    /// arm：当前行的 literal pool 地址（pc 相对 ldr 用）。
    pub(crate) literal: Option<u64>,
    /// mips：持回的转移（延迟槽语义：(mnemonic, body)）。
    pub(crate) delayed: Option<(String, String)>,
    /// mips：GOT 槽值注释（`# <addr>`，state_got_values 注入；load_value 读）。
    pub(crate) got_value: Option<i64>,
}

impl State {
    pub fn new(arch: AbiArch, sp: &str, pc: &str, bp: Option<&str>) -> Self {
        let registers = RegisterFile::build(&abi::registers(arch), &abi::narrow_views(arch));
        State {
            arch,
            registers,
            sp: sp.to_string(),
            pc: pc.to_string(),
            bp: bp.map(|s| s.to_string()),
            refused_line: None,
            constraints: Vec::new(),
            deferred_reads: Vec::new(),
            closed_fds: Vec::new(),
            flags: None,
            pending: None,
            mem: HashMap::new(),
            derived_writes: Vec::new(),
            line_addr: 0,
            thumb: false,
            prev_addr: 0,
            literal: None,
            delayed: None,
            got_value: None,
        }
    }

    pub fn bits(&self) -> u32 {
        match self.arch {
            AbiArch::Amd64 | AbiArch::Aarch64 | AbiArch::Riscv64 => 64,
            AbiArch::I386 | AbiArch::Arm | AbiArch::Mips => 32,
        }
    }

    pub fn size_t(&self) -> i64 {
        (self.bits() / 8) as i64
    }

    /// 全 1 掩码（64 位用 i64::MAX 近似——master 任意精度在此处只做 & mask）。
    pub fn width_mask(&self) -> u64 {
        if self.bits() == 64 { u64::MAX } else { u32::MAX as u64 }
    }

    pub fn register(&self, name: &str) -> bool {
        self.registers.contains(name)
    }

    pub fn check_register(&self, reg: &str) -> EmuResult<()> {
        if self.register(reg) {
            Ok(())
        } else {
            Err(EmuError::InstructionArgument(format!("{reg:?} is not a valid register")))
        }
    }

    /// 寄存器 predefined 快照。
    pub fn reg_map(&self) -> HashMap<String, Val> {
        let mut m = HashMap::new();
        for name in abi::registers(self.arch) {
            m.insert(name.clone(), self.registers.get(&name));
        }
        m
    }

    /// arg_to_lambda。
    pub fn arg_val(&self, arg: &str) -> EmuResult<Val> {
        let arg = arg.trim();
        if self.register(arg) {
            return Ok(self.registers.get(arg));
        }
        parse_val(arg, &self.reg_map())
            .map_err(|_| EmuError::InstructionArgument(format!("cannot parse operand {arg:?}")))
    }

    /// value_of（DataProcessing/arith 用）。
    pub fn value_of(&self, arg: &str) -> EmuResult<Val> {
        self.arg_val(arg)
    }

    pub fn err_unsupported_pub(inst: &str, args: &[&str]) -> EmuError {
        err_unsupported(inst, args)
    }

    // ---- 安全调用 ----

    pub fn dispatch_safe_call(&mut self, addr: &str) -> EmuResult<()> {
        let Some((_, reqs)) = SAFE_CALLS.iter().find(|(n, _)| addr.contains(n)) else {
            return Err(EmuError::UnsupportedInstructionArgument(format!("call {addr}")));
        };
        for (idx, req) in reqs.iter().copied() {
            match req {
                PtrReq::ClosedFd => {
                    let fd = self.argument(idx);
                    if !matches!(fd, Val::Int(_)) {
                        self.closed_fds.push(fd.to_string());
                    }
                }
                PtrReq::GlobalVar => {
                    let arg = self.argument(idx);
                    if !self.global_var(&arg.to_string()) {
                        return Err(EmuError::UnsupportedInstructionArgument(format!(
                            "arg not global: {arg}"
                        )));
                    }
                }
                PtrReq::Writable | PtrReq::Deref | PtrReq::NullableDeref | PtrReq::Null => {
                    let arg = self.argument(idx);
                    self.record_pointer(arg, req)?;
                }
            }
        }
        self.clobber_caller_saved();
        Ok(())
    }

    pub fn clobber_caller_saved(&mut self) {
        for reg in &abi::caller_saved(self.arch) {
            if self.registers.contains(reg) {
                self.registers.set(reg, Val::Clobbered);
            }
        }
        if let Some(reg) = abi::return_register(self.arch) {
            if self.registers.contains(reg) {
                self.registers.set(reg, Val::Int(0));
            }
        }
    }

    /// record_pointer。
    pub fn record_pointer(&mut self, arg: Val, req: PtrReq) -> EmuResult<()> {
        if let Val::Int(v) = &arg {
            if *v == 0 && matches!(req, PtrReq::NullableDeref | PtrReq::Null) {
                return Ok(());
            }
            return Err(EmuError::UnsupportedInstructionArgument(format!(
                "literal pointer arg {arg}"
            )));
        }
        let Val::Lambda(l) = &arg else {
            return Err(EmuError::UnsupportedInstructionArgument(format!(
                "non-lambda pointer {arg}"
            )));
        };
        match req {
            PtrReq::Writable => self.add_writable(l.clone()),
            PtrReq::Deref => self.deferred_reads.push((arg.clone(), false)),
            PtrReq::NullableDeref => self.deferred_reads.push((arg.clone(), true)),
            PtrReq::Null => {
                if self.mapped_nonnull_pointer(l) {
                    return Err(EmuError::UnsupportedInstructionArgument(format!(
                        "cannot be NULL: {arg}"
                    )));
                }
                self.constraints.push(CtItem::Raw(format!("{arg} == NULL")));
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    pub fn needs_writable(&self, l: &Lambda) -> bool {
        let obj = l.obj_str();
        !(obj == self.sp || obj == self.pc || obj == "$base")
    }

    pub fn add_writable(&mut self, l: Lambda) {
        if self.needs_writable(&l) {
            self.constraints.push(CtItem::Writable(l));
        }
    }

    /// global_var?（emulator 侧：包含 pc 名）。
    pub fn global_var(&self, s: &str) -> bool {
        s.contains(&self.pc)
    }

    pub fn is_clobbered(&self, v: &Val) -> bool {
        matches!(v, Val::Clobbered)
    }

    pub fn mapped_pointer(&self, obj: &str) -> bool {
        obj.contains(&self.sp) || obj == "$base" || self.global_var(obj)
    }

    fn mapped_nonnull_pointer(&self, l: &Lambda) -> bool {
        l.deref_count == 0 && self.mapped_pointer(&l.obj_str())
    }

    // ---- 终端调用与参数 ----

    pub fn reach_terminal_call(&mut self, addr: &str) -> EmuError {
        self.registers.set(&self.pc.clone(), Val::Str(addr.to_string()));
        EmuError::UnsupportedInstructionArgument("__terminal__".into())
    }

    /// argument（arch 通用表；arm/riscv64 特殊在各自模块覆写路径）。
    pub fn argument(&self, idx: usize) -> Val {
        match self.arch {
            AbiArch::Aarch64 => self.registers.get(&format!("x{idx}")),
            AbiArch::Riscv64 => self.registers.get(&format!("a{idx}")),
            AbiArch::Arm => {
                if idx < 4 {
                    self.registers.get(&format!("r{idx}"))
                } else {
                    self.stack_arg(idx)
                }
            }
            AbiArch::Mips => {
                if idx < 4 {
                    self.registers.get(&format!("a{idx}"))
                } else {
                    // master mips.rb：`top + idx * size_t` —— o32 为每个参数保留
                    // 栈槽（含前 4 个寄存器参数的 caller 侧槽位）
                    self.stack_get_val(&Lambda::reg(&self.sp).add(idx as i64 * self.size_t()).deref())
                }
            }
            AbiArch::Amd64 => match idx {
                0 => self.registers.get("rdi"),
                1 => self.registers.get("rsi"),
                2 => self.registers.get("rdx"),
                3 => self.registers.get("rcx"),
                4 => self.registers.get("r8"),
                5 => self.registers.get("r9"),
                _ => Val::Clobbered,
            },
            AbiArch::I386 => {
                let off = idx as i64 * self.size_t();
                self.stack_get_val(&Lambda::reg(&self.sp).add(off).deref())
            }
        }
    }

    fn stack_arg(&self, idx: usize) -> Val {
        // arm：r0-r3 之后的参数在 [sp+(idx-4)*4]
        let off = (idx as i64 - 4) * self.size_t();
        self.stack_get_val(&Lambda::reg(&self.sp).add(off).deref())
    }

    fn stack_get_val(&self, slot: &Lambda) -> Val {
        if let Some(v) = self.stored_value(&Val::Lambda(slot.clone())) {
            return v;
        }
        Val::Lambda(slot.clone())
    }

    pub fn libc_base(&self) -> Lambda {
        Lambda::libc_base()
    }
}

/// 一行的 mnemonic（`4a1c0: cmp x2, 1` → `cmp`；无地址行容忍）。
pub fn mnemonic_of(cmd: &str) -> &str {
    let s = cmd.trim_start();
    let after = if let Some(colon) = s.find(':') {
        if !s[..colon].is_empty() && s[..colon].chars().all(|c| c.is_ascii_hexdigit()) && colon <= 16 {
            s[colon + 1..].trim_start()
        } else {
            s
        }
    } else {
        s
    };
    after.split_whitespace().next().unwrap_or("")
}

/// 行地址（branch_addr：`4a200: nop` → 0x4a200）。
pub fn addr_of_line(cmd: &str) -> u64 {
    let s = cmd.trim_start();
    let end = s.find(':').unwrap_or(0);
    let hex = if end > 0 { &s[..end] } else { "" };
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

/// 操作数切分（跳过地址与 mnemonic token；逗号按括号深度；剥大小提示）。
/// 不剥 `#`（aarch64 的 operands() 自行处理）；arm literal pool 注释在 fetcher 层已去。
/// `#-?(0x)?[0-9a-f]+` → 去 '#'（master `cmd.gsub(/#-?(0x)?[0-9a-f]+/) { |v| v[1..] }`）。
fn strip_hash_imms(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'-' {
                j += 1;
            }
            let mut k = j;
            if k + 1 < bytes.len() && bytes[k] == b'0' && (bytes[k + 1] == b'x') {
                k += 2;
            }
            let hexstart = k;
            while k < bytes.len() && bytes[k].is_ascii_hexdigit() {
                k += 1;
            }
            if k > hexstart {
                // 匹配：去 '#'，保留其余
                out.push_str(&s[i + 1..k]);
                i = k;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

pub fn split_operands(cmd: &str) -> Vec<String> {
    let s = cmd.trim();
    // 跳过 `addr:` 前缀
    let rest = if let Some(colon) = s.find(':') {
        if !s[..colon].is_empty() && s[..colon].chars().all(|c| c.is_ascii_hexdigit()) && colon <= 16 {
            s[colon + 1..].trim_start()
        } else {
            s
        }
    } else {
        s
    };
    // 跳过 mnemonic（首个空白分隔 token）
    let after_mnem = match rest.find(char::is_whitespace) {
        Some(i) => &rest[i..],
        None => return vec![],
    };
    // Ruby aarch64/arm process! 的 gsub：`#-?0x?[0-9a-f]+` → 去 '#'（立即数标记）
    let stripped = strip_hash_imms(after_mnem);
    let after_mnem = stripped.as_str();
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in after_mnem.chars() {
        if c == ',' && depth == 0 {
            if !cur.trim().is_empty() {
                args.push(cur.trim().to_string());
            }
            cur = String::new();
            continue;
        }
        cur.push(c);
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            _ => {}
        }
    }
    if !cur.trim().is_empty() {
        args.push(cur.trim().to_string());
    }
    for a in args.iter_mut() {
        for kw in ["XMMWORD", "QWORD", "DWORD", "WORD", "BYTE", "PTR"] {
            *a = a.replace(kw, "");
        }
        *a = a.trim().to_string();
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_call() {
        assert!(is_terminal_call("execve"));
        assert!(is_terminal_call("posix_spawn"));
        assert!(is_terminal_call("posix_spawnp"));
        assert!(is_terminal_call("execl"));
        assert!(is_terminal_call("execv"));
        assert!(is_terminal_call("execvp"));
        assert!(is_terminal_call("execveat"));
        assert!(!is_terminal_call("posix_spawnattr_init"));
        assert!(!is_terminal_call("execfx"));
        assert!(!is_terminal_call("fork"));
    }

    #[test]
    fn test_mnemonic_and_addr() {
        assert_eq!(mnemonic_of("4a1d0: b.ne 4a200 <foo>"), "b.ne");
        assert_eq!(mnemonic_of("  4a1c0:\tcmp\tx2, 1"), "cmp");
        assert_eq!(mnemonic_of("4a1c0: cmp x2, 1"), "cmp");
        assert_eq!(addr_of_line("4a200: nop"), 0x4a200);
        assert_eq!(addr_of_line("  9cec8:\tbl"), 0x9cec8);
    }

    #[test]
    fn test_split_operands() {
        assert_eq!(
            split_operands("1000: ldr x0, [sp, #96]"),
            vec!["x0", "[sp, 96]"]
        );
        assert_eq!(split_operands("1000: add x29, sp, #0x10"), vec!["x29", "sp", "0x10"]);
        assert_eq!(
            split_operands("1000: mov rdx, QWORD PTR [rsp+0x8]"),
            vec!["rdx", "[rsp+0x8]"]
        );
        // 括号内逗号不切
        assert_eq!(split_operands("1: stp x29, x30, [sp, -0x20]"), vec!["x29", "x30", "[sp, -0x20]"]);
    }

    #[test]
    fn test_register_file_narrow() {
        let names = abi::registers(AbiArch::Aarch64);
        let mut rf = RegisterFile::build(&names, &abi::narrow_views(AbiArch::Aarch64));
        // entry 值：w0 读为 w0 自身
        assert_eq!(rf.get("w0").to_string(), "w0");
        assert_eq!(rf.get("x0").to_string(), "x0");
        // 写 x0 后 w0 读同一值
        rf.set("x0", Val::Int(5));
        assert_eq!(rf.get("w0"), Val::Int(5));
        // 写 w0（窄名写全存储）
        rf.set("w1", Val::Int(7));
        assert_eq!(rf.get("x1"), Val::Int(7));
        // 常量寄存器
        rf.set("xzr", Val::Int(0));
        assert_eq!(rf.get("xzr"), Val::Int(0));
    }

    #[test]
    fn test_safe_calls_order() {
        // 具体前缀在泛化前
        let idx_specific = SAFE_CALLS.iter().position(|(n, _)| *n == "posix_spawnattr_setsigmask").unwrap();
        let idx_generic = SAFE_CALLS.iter().position(|(n, _)| *n == "posix_spawnattr_").unwrap();
        assert!(idx_specific < idx_generic);
    }
}
