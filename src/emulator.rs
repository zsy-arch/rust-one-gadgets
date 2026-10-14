//! 符号执行：对齐 one_gadget **v1.10.0** 的 `Emulators::Amd64`。
//!
//! 与新版（2.x）emulator 的关键差异——本模块逐条对齐 1.10.0（参考输出即由它生成）：
//! - 仅 13 条指令：add/call/jmp/lea/mov/nop/push/sub/xor/movq/movaps/movhps/punpcklqdq
//! - **没有** jcc/cmp/test/endbr/xchg/movsxd/and/shr——遇到即 refused（模拟停止）
//! - 安全调用（sigprocmask/__close/unsetenv/__sigaction）**不 clobber** 寄存器
//! - 内存仅跟踪 sp/bp 两张栈表；store 记 `writable:`（rip 基地址除外）；
//!   `constraints` 输出时 writable 按 deref==0 归并为基名、其余按整体渲染，去重后排序
//! - `mov rdi,[rbp-0x48]`（即使写过该槽）得到 `[rbp-0x48]` lambda——**无读回**；
//!   `movq/movhps xmm,[sp+off]` 读的是栈表（lazy 物化 `[rsp+off]`）
//! - 寄存器窄名（eax）与全名（rax）**相互独立**
//! - rip-relative 保持符号：`lea rdi,[rip+0x187c2e]` → `rdi = rip+0x187c2e`
//! - 值可以是整数（`mov rdi, 0x30`、`xor edx,edx`、`push 0x10` 落栈为 16）

use std::collections::HashMap;

use crate::lambda::{parse_operand, Lambda, Val};

/// amd64 寄存器全集（= `ABI.amd64`，X86_32 + 64 位扩展 + xmm8-15）。
pub const AMD64_REGS: &[&str] = &[
    "eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
];

/// i386 寄存器全集（= `ABI.i386` = X86_32）。
pub const I386_REGS: &[&str] = &[
    "eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
];

/// 栈寄存器判定（= `ABI.stack_register?`）。
pub fn is_stack_register(reg: &str) -> bool {
    matches!(reg, "esp" | "ebp" | "rsp" | "rbp" | "sp" | "x29")
}

/// 一张 1.10.0 语义的栈表：offset → 值；未写过的键读取时 lazy 物化。
#[derive(Default)]
struct StackTable {
    /// 已物化的槽（含 lazy 生成后再被覆盖的情况——1.10.0 的 Hash.new 语义）。
    slots: HashMap<i64, Val>,
}

impl StackTable {
    /// 读取：写过的返回写入值，否则 lazy 物化为 `[<base>+off]`。
    fn get_or_materialize(&mut self, off: i64, base: &str) -> Val {
        self.slots.entry(off).or_insert_with(|| {
            Val::Lambda(Lambda::reg(base).add_imm(off).deref())
        }).clone()
    }
    /// 只在写过的前提下读（residual 用）。
    fn get_if_written(&self, off: i64) -> Option<Val> {
        self.slots.get(&off).cloned()
    }
    fn insert(&mut self, off: i64, val: Val) {
        self.slots.insert(off, val);
    }
}

/// 约束中间表示（渲染前的结构化形式）。
#[derive(Clone, Debug, PartialEq)]
pub enum Constraint {
    /// `writable: <lambda>`（结构化，供 uniq 归并）
    Writable(Lambda),
    /// 原样文本
    Raw(String),
}

/// 模拟一个候选后缀后的处理器状态。
pub struct Emulator {
    /// 目标架构（决定寄存器表/字长/xmm lane 数/参数读取）。
    arch: crate::elf::Arch,
    /// 寄存器名 → 值（Lambda / Const / Xmm）。
    regs: HashMap<String, Val>,
    /// sp / bp 栈表。
    sp_stack: StackTable,
    bp_stack: StackTable,
    /// 顺序收集的约束。
    constraints: Vec<Constraint>,
    /// 终点 call 的目标行（`eb0f0 <execve@@GLIBC_2.2.5>`）。
    pub terminal_call: Option<String>,
    /// 首个 refused 行文本（调试用）。
    pub refused_line: Option<String>,
}

/// 处理一条指令的结果。
enum Step { Continue, Terminal, Fail }

impl Emulator {
    /// 按架构构造（amd64 / i386）。
    pub fn new(arch: crate::elf::Arch) -> Self {
        let (reg_list, xmm_count) = match arch {
            crate::elf::Arch::X64 => (AMD64_REGS, 16usize),
            _ => (I386_REGS, 8usize),
        };
        let mut regs = HashMap::new();
        for r in reg_list {
            regs.insert((*r).to_string(), Val::Lambda(Lambda::reg(r)));
        }
        // xmm lanes —— 名字即 `(uN)xmmI` / `(uN)(xmmI >> N*I)`（Ruby to_lambda）：
        // 64 位 2 lane (u64)，32 位 4 lane (u32)
        let bits = match arch {
            crate::elf::Arch::X64 => 64u32,
            _ => 32u32,
        };
        for i in 0..xmm_count {
            let name = format!("xmm{i}");
            let lanes: Vec<Box<Val>> = (0..(128 / bits))
                .map(|l| {
                    let cast = format!("(u{bits})");
                    let nm = if l == 0 {
                        format!("{cast}xmm{i}")
                    } else {
                        format!("{cast}(xmm{i} >> {})", bits * l)
                    };
                    Box::new(Val::Lambda(Lambda::reg(&nm)))
                })
                .collect();
            regs.insert(name, Val::Xmm(lanes));
        }
        Emulator {
            arch,
            regs,
            sp_stack: StackTable::default(),
            bp_stack: StackTable::default(),
            constraints: Vec::new(),
            terminal_call: None,
            refused_line: None,
        }
    }

    /// 字长（字节）：push/argv/envp 槽距。
    pub fn size_t_of(&self) -> i64 {
        self.size_t()
    }

    /// 字长（字节）：push/argv/envp 槽距。
    fn size_t(&self) -> i64 {
        match self.arch {
            crate::elf::Arch::X64 => 8,
            _ => 4,
        }
    }

    /// sp 寄存器名（渲染文本用）。
    fn sp_name(&self) -> &'static str {
        match self.arch {
            crate::elf::Arch::X64 => "rsp",
            _ => "esp",
        }
    }

    /// bp 寄存器名。
    fn bp_name(&self) -> &'static str {
        match self.arch {
            crate::elf::Arch::X64 => "rbp",
            _ => "ebp",
        }
    }

    /// 参数读取：amd64 = SysV 寄存器；i386 = 栈槽 sp_stack[cur_top + idx*4]
    /// （cur_top = esp.evaluate({esp:0})，即当前 esp 的 imm）。
    pub fn argument(&self, idx: usize) -> Val {
        match self.arch {
            crate::elf::Arch::X64 => {
                let name = match idx {
                    0 => "rdi",
                    1 => "rsi",
                    2 => "rdx",
                    3 => "rcx",
                    4 => "r8",
                    5 => "r9",
                    _ => return Val::Const(0),
                };
                self.get_reg(name)
            }
            _ => {
                // esp 当前值必须是可求值的 bare sp lambda
                let Val::Lambda(sp_l) = self.get_reg("esp") else { return Val::Const(0) };
                if sp_l.deref_count != 0 {
                    return Val::Const(0);
                }
                // 只接受直接 esp 基（嵌套 = evaluate raise → argument 会炸 → 该后缀无 gadget）
                let top = match &sp_l.base {
                    crate::lambda::Base::Reg(r) if r.as_ref() == self.sp_name() => sp_l.imm,
                    _ => return Val::Const(0),
                };
                // 读槽（可能 lazy 物化——直接构造 [esp+off] lambda 文本）
                let off = top + self.size_t() * idx as i64;
                self.sp_stack.get_if_written(off).unwrap_or_else(|| {
                    Val::Lambda(Lambda::reg(self.sp_name()).add_imm(off).deref())
                })
            }
        }
    }

    fn get_reg(&self, name: &str) -> Val {
        self.regs.get(name).cloned().unwrap_or(Val::Lambda(Lambda::reg(name)))
    }

    fn set_reg(&mut self, name: &str, val: Val) {
        self.regs.insert(name.to_string(), val);
    }

    /// 执行一条指令（操作数文本，如 `lea rbp,[rsp+0x220]`）；
    /// false = 停止（终点或 refused）。
    pub fn step(&mut self, text: &str) -> bool {
        let out = self.step_inner(text);
        if matches!(out, Step::Fail) && self.refused_line.is_none() {
            self.refused_line = Some(text.to_string());
        }
        // Terminal 也返回 false：调用方经 terminal_call 字段区分停止原因
        !matches!(out, Step::Fail | Step::Terminal)
    }

    fn step_inner(&mut self, text: &str) -> Step {
        // 1.10.0 的指令匹配基于文本助记符 + 操作数个数
        let (mnem, args) = match split_mnemonic(text) {
            Some(x) => x,
            None => return Step::Fail, // objdump 不认识的行
        };
        let args: Vec<String> = args.iter().map(|a| strip_size_prefix(a)).collect();

        match mnem {
            "jmp" => Step::Continue, // 走图已缝合（fetcher 已处理）
            "call" => self.inst_call(&args[0]),
            "lea" => self.inst_lea(&args[0], &args[1]),
            "mov" => self.inst_mov(&args[0], &args[1]),
            "nop" => Step::Continue,
            "push" => self.inst_push(&args[0]),
            "add" => self.inst_add(&args[0], &args[1]),
            "sub" => self.inst_sub(&args[0], &args[1]),
            "xor" => self.inst_xor(&args[0], &args[1]),
            "movq" => self.inst_movq(&args[0], args.get(1).map(|s| s.as_str()).unwrap_or("")),
            "movaps" => self.inst_movaps(&args[0], &args[1]),
            "movhps" => self.inst_movhps(&args[0], &args[1]),
            "punpcklqdq" => self.inst_punpcklqdq(&args[0], &args[1]),
            _ => Step::Fail,
        }
    }

    // ---------- 指令实现（对齐 x86.rb 1.10.0） ----------

    fn inst_mov(&mut self, dst: &str, src: &str) -> Step {
        // src → Lambda/Int（predefined 替换）
        let src_val = match parse_operand(src, &self.regs) {
            Ok(v) => v,
            Err(_) => return Step::Fail,
        };
        if is_register_arch(dst, self.arch) {
            self.set_reg(dst, src_val);
            return Step::Continue;
        }
        // 内存目标
        let dst_l = match parse_operand(dst, &self.regs) {
            Ok(Val::Lambda(l)) => l,
            _ => return Step::Fail,
        };
        self.add_writable(&dst_l);
        // 只跟踪 sp/bp 栈表
        let sp_name = self.sp_name();
        let Some((stack, base)) = self.stack_of(&dst_l) else { return Step::Continue };
        if dst_l.deref_count != 1 {
            return Step::Continue;
        }
        let Ok(addr) = dst_l.clone().ref_() else { return Step::Fail };
        let Ok(off) = eval_offset(&addr, sp_name) else { return Step::Fail };
        let _ = base;
        stack.insert(off, src_val);
        Step::Continue
    }

    /// movaps：仅支持 `movaps [sp+off], xmm`。
    fn inst_movaps(&mut self, dst: &str, src: &str) -> Step {
        // movaps 的 xmm 在 src 侧、内存在 dst 侧——交换后走统一检查
        let Some((xmm_name, dst_l)) = check_xmm_sp(src, dst, &self.regs, self.arch, self.sp_name()) else {
            return Step::Fail;
        };
        // 对齐约束：sp & 0xf == (0x10 - off) & 0xf（Ruby 整数插值 → 十进制）
        let Ok(off) = eval_offset(&dst_l, self.sp_name()) else { return Step::Fail };
        self.constraints
            .push(Constraint::Raw(format!("{} & 0xf == {}", self.sp_name(), (0x10 - off) & 0xf)));
        if let Val::Xmm(lanes) = self.get_reg(xmm_name) {
            for (i, lane) in lanes.iter().enumerate() {
                self.sp_stack.insert(off + (i as i64) * self.size_t(), (**lane).clone());
            }
        }
        Step::Continue
    }

    /// movq：`movq xmm, r64`（低 lane，仅 64 位）或 `movq xmm, [sp+off]`。
    fn inst_movq(&mut self, dst: &str, src: &str) -> Step {
        // movq xmm, r64（Ruby: self.class.bits == 64 才支持）
        if self.arch == crate::elf::Arch::X64
            && dst.starts_with("xmm")
            && is_register_arch(src, self.arch)
            && src.starts_with('r')
        {
            let v = self.get_reg(src);
            return self.set_xmm_lane(dst, 0, v);
        }
        // movq xmm, [sp+off]：64/bits 个槽写 lane0 起
        let Some((xmm, mem_l)) = check_xmm_sp(dst, src, &self.regs, self.arch, self.sp_name()) else {
            return Step::Fail;
        };
        let Ok(off) = eval_offset(&mem_l, self.sp_name()) else { return Step::Fail };
        let count = 64 / match self.arch { crate::elf::Arch::X64 => 64u32, _ => 32 };
        for i in 0..count as usize {
            let v = self.sp_stack.get_or_materialize(off + (i as i64) * self.size_t(), self.sp_name());
            if matches!(self.set_xmm_lane(xmm, i, v), Step::Fail) {
                return Step::Fail;
            }
        }
        Step::Continue
    }

    /// movhps：`movhps xmm, [sp+off]`（lane 64..128，i386 是 lane 2-3）。
    fn inst_movhps(&mut self, dst: &str, src: &str) -> Step {
        let Some((xmm, mem_l)) = check_xmm_sp(dst, src, &self.regs, self.arch, self.sp_name()) else {
            return Step::Fail;
        };
        let Ok(off) = eval_offset(&mem_l, self.sp_name()) else { return Step::Fail };
        let bits = match self.arch { crate::elf::Arch::X64 => 64u32, _ => 32 };
        let start = (64 / bits) as usize;
        let count = (64 / bits) as usize;
        for i in 0..count {
            let lane = start + i;
            let v = self
                .sp_stack
                .get_or_materialize(off + (i as i64) * self.size_t(), self.sp_name());
            if matches!(self.set_xmm_lane(xmm, lane, v), Step::Fail) {
                return Step::Fail;
            }
        }
        Step::Continue
    }

    fn set_xmm_lane(&mut self, xmm: &str, lane: usize, v: Val) -> Step {
        let Some(Val::Xmm(mut lanes)) = self.regs.get(xmm).cloned() else { return Step::Fail };
        lanes[lane] = Box::new(v);
        self.set_reg(xmm, Val::Xmm(lanes));
        Step::Continue
    }

    /// punpcklqdq：dst[64:128] = src[0:64]（i386：lane2-3 = lane0-1）。
    fn inst_punpcklqdq(&mut self, dst: &str, src: &str) -> Step {
        if !dst.starts_with("xmm") || !src.starts_with("xmm") {
            return Step::Fail;
        }
        let bits = match self.arch { crate::elf::Arch::X64 => 64u32, _ => 32 };
        let start = (64 / bits) as usize;
        let count = (64 / bits) as usize;
        let (d, s) = (self.get_reg(dst), self.get_reg(src));
        if let (Val::Xmm(mut dl), Val::Xmm(sl)) = (d, s) {
            for i in 0..count {
                dl[start + i] = sl[i].clone();
            }
            self.set_reg(dst, Val::Xmm(dl));
            return Step::Continue;
        }
        Step::Fail
    }

    fn inst_lea(&mut self, dst: &str, src: &str) -> Step {
        if !is_register_arch(dst, self.arch) {
            return Step::Fail;
        }
        // Ruby: registers[dst] = arg_to_lambda(src).ref!
        // —— src 整体（含 []）先 parse（predefined 折叠），再剥一层 deref
        match parse_operand(src, &self.regs) {
            Ok(Val::Lambda(l)) => {
                if l.deref_count == 0 {
                    return Step::Fail; // ref! 会抛（lea reg, reg 形式 objdump 不产）
                }
                let Ok(r) = l.ref_() else { return Step::Fail };
                self.set_reg(dst, Val::Lambda(r));
                Step::Continue
            }
            _ => Step::Fail,
        }
    }

    fn inst_push(&mut self, val: &str) -> Step {
        let v = match parse_operand(val, &self.regs) {
            Ok(v) => v,
            Err(_) => return Step::Fail,
        };
        // sp -= size_t（Ruby registers[sp] -= size_t：bare 或 +imm 均可，
        // 只要 evaluate 后是 Integer；嵌套/op 变体则视为 corrupted sp）
        let sp = self.get_reg(self.sp_name());
        let new_sp = match sp {
            Val::Lambda(l)
                if l.deref_count == 0
                    && l.op.is_none()
                    && l.root_name_str() == Some(self.sp_name()) =>
            {
                Val::Lambda(l.add_imm(-self.size_t()))
            }
            _ => return Step::Fail, // corrupted sp
        };
        self.set_reg(self.sp_name(), new_sp);
        // cur_top = evaluate({sp:0}) = imm
        let Val::Lambda(sp_l) = self.get_reg(self.sp_name()) else { return Step::Fail };
        let Ok(top) = eval_offset(&sp_l, self.sp_name()) else { return Step::Fail };
        self.sp_stack.insert(top, v);
        Step::Continue
    }

    fn inst_xor(&mut self, dst: &str, src: &str) -> Step {
        if !is_register_arch(dst, self.arch) || dst != src {
            return Step::Fail;
        }
        // 窄名 → 全名（1.10.0: dst[0]='r' if e-prefix；仅 amd64——
        // i386 的 ABI 表本身就有 e 名，无需提升）
        let name = match self.arch {
            crate::elf::Arch::X64 if dst.starts_with('e') => format!("r{}", &dst[1..]),
            _ => dst.to_string(),
        };
        self.set_reg(&name, Val::Const(0));
        Step::Continue
    }

    fn inst_add(&mut self, dst: &str, src: &str) -> Step {
        if !is_register_arch(dst, self.arch) {
            return Step::Fail;
        }
        let rhs = match parse_operand(src, &self.regs) {
            Ok(Val::Const(c)) => c,
            // add reg, reg：1.10.0 要求 src 为 Numeric，Lambda 则 raise → refused。
            // 实测 add rax, rbx → false。
            _ => return Step::Fail,
        };
        let lhs = self.get_reg(dst);
        let result = match lhs {
            Val::Const(c) => Val::Const(c + rhs),
            Val::Lambda(l) => Val::Lambda(l.add_imm(rhs)),
            _ => return Step::Fail,
        };
        self.set_reg(dst, result);
        Step::Continue
    }

    fn inst_sub(&mut self, dst: &str, src: &str) -> Step {
        if !is_register_arch(dst, self.arch) {
            return Step::Fail;
        }
        let rhs = match parse_operand(src, &self.regs) {
            Ok(Val::Const(c)) => c,
            _ => return Step::Fail, // sub reg, reg 拒绝
        };
        let lhs = self.get_reg(dst);
        let result = match lhs {
            Val::Const(c) => Val::Const(c - rhs),
            Val::Lambda(l) => Val::Lambda(l.add_imm(-rhs)),
            _ => return Step::Fail,
        };
        self.set_reg(dst, result);
        Step::Continue
    }

    // ---------- 调用 ----------

    fn inst_call(&mut self, addr: &str) -> Step {
        // 终点：execve / execl / posix_spawn（任意包含）
        if ["execve", "execl", "posix_spawn"].iter().any(|n| addr.contains(n)) {
            self.terminal_call = Some(addr.to_string());
            return Step::Terminal;
        }
        // 安全调用（1.10.0 checker 表）
        if addr.contains("sigprocmask") || addr.contains("__close") {
            return Step::Continue;
        }
        if addr.contains("unsetenv") {
            // arg0 须为 global_var（含 rip）
            let a0 = self.argument(0).to_string();
            return if a0.contains("rip") { Step::Continue } else { Step::Fail };
        }
        if addr.contains("__sigaction") {
            let a1 = self.argument(1).to_string();
            let a2 = self.argument(2);
            return if a1.contains("rip") && matches!(a2, Val::Const(0)) {
                Step::Continue
            } else {
                Step::Fail
            };
        }
        Step::Fail
    }

    // ---------- 内存/约束 ----------

    /// 地址 lambda 属于哪张栈表（子串匹配，对齐 get_corresponding_stack）。
    fn stack_of(&mut self, l: &Lambda) -> Option<(&mut StackTable, &'static str)> {
        let s = l.to_string();
        let (sp, bp) = (self.sp_name(), self.bp_name());
        if s.contains(sp) {
            Some((&mut self.sp_stack, sp))
        } else if s.contains(bp) {
            Some((&mut self.bp_stack, bp))
        } else {
            None
        }
    }

    /// store 目标 → writable 约束（rip 基地址豁免）。
    fn add_writable(&mut self, dst: &Lambda) {
        // add_writable: ref! 剥一层 deref；obj == pc(rip) 豁免
        let Ok(l) = dst.clone().ref_() else { return };
        if matches!(l.root_name_str(), Some("rip")) {
            return;
        }
        self.constraints.push(Constraint::Writable(l));
    }

    // ---------- resolver 侧快照 ----------

    pub fn constraints_snapshot(&self) -> Vec<Constraint> {
        self.constraints.clone()
    }

    pub fn regs_snapshot(&self) -> HashMap<String, Val> {
        self.regs.clone()
    }

    /// 按 lambda 根寄存器取栈视图（sp/bp）。
    pub fn stack_of_root(&self, l: &Lambda) -> StackView<'_> {
        let name = l.to_string();
        let (sp, bp) = (self.sp_name(), self.bp_name());
        if name.contains(sp) {
            StackView { table: &self.sp_stack, base: sp }
        } else {
            StackView { table: &self.bp_stack, base: bp }
        }
    }
}

/// resolver 读取栈表的只读视图（lazy 物化值按渲染文本模拟）。
pub struct StackView<'a> {
    table: &'a StackTable,
    base: &'static str,
}

impl<'a> StackView<'a> {
    /// 读取 off：写过的值渲染；未写的渲染 `[base+off]`。
    pub fn get_or(&self, off: i64) -> String {
        match self.table.get_if_written(off) {
            Some(v) => v.to_string(),
            None => Lambda::reg(self.base).add_imm(off).deref().to_string(),
        }
    }
}

// ---------- 模块级工具 ----------

/// 助记符 + 操作数切分（`mov rsi, r10` → ("mov", ["rsi","r10"])）。
fn split_mnemonic(text: &str) -> Option<( &str, Vec<String>)> {
    crate::disasm::split_mnemonic_operands(text)
}

/// 去掉 `QWORD PTR ` 等尺寸前缀（fetch_args 的 gsub）。
fn strip_size_prefix(a: &str) -> String {
    // 1.10.0: arg.gsub(/XMMWORD|QWORD|DWORD|WORD|BYTE|PTR/, '').strip
    let mut s = a.to_string();
    for kw in ["XMMWORD", "QWORD", "DWORD", "WORD", "BYTE", "PTR"] {
        s = s.replace(kw, "");
    }
    s.trim().to_string()
}

/// 是否合法寄存器名（按架构 ABI 表）。
fn is_register_arch(name: &str, arch: crate::elf::Arch) -> bool {
    match arch {
        crate::elf::Arch::X64 => AMD64_REGS.contains(&name),
        _ => I386_REGS.contains(&name),
    }
}

/// (xmm, mem) 是否是 `(xmm, [sp+off])` 形态（check_xmm_sp）。
/// 入参顺序对齐 1.10.0 `check_xmm_sp(dst, src)`——dst 是数据去向侧（xmm 或栈）。
/// 这里统一：a 是 xmm 侧、b 是内存侧。返回 (xmm 名, 内存地址 lambda)。
fn check_xmm_sp<'a>(
    a: &'a str,
    b: &str,
    regs: &HashMap<String, Val>,
    arch: crate::elf::Arch,
    sp: &str,
) -> Option<(&'a str, Lambda)> {
    if !(a.starts_with("xmm") && is_register_arch(a, arch)) {
        return None;
    }
    if !b.contains(sp) {
        return None;
    }
    // 与 inst_lea 同理：对完整含 [] 操作数 parse（deref=1）再 ref! 剥层
    let Val::Lambda(l) = parse_operand(b, regs).ok()? else { return None };
    if l.deref_count != 1 {
        return None;
    }
    let Ok(addr) = l.ref_() else { return None };
    Some((a, addr))
}

/// `rsp+0x10` 形式的 offset 求值（evaluate({rsp:0, rbp:0})）。
///
/// Ruby `Lambda#evaluate` 只会查 eval_dict 里的**字符串寄存器名**；
/// obj 是嵌套 Lambda（如 `[[rbp-0x78]+0x10]` 剥层后的 `[rbp-0x78]+0x10`）
/// 或带运算时直接 raise → process false → 模拟停止。这里对齐：
/// 只接受直接的 rsp/rbp/esp/ebp 基，Nested/LibcBase/op 一律 Err。
fn eval_offset(l: &Lambda, _sp: &str) -> Result<i64, ()> {
    if l.deref_count != 0 || l.op.is_some() {
        return Err(());
    }
    match &l.base {
        crate::lambda::Base::Reg(r)
            if matches!(r.as_ref(), "rsp" | "rbp" | "esp" | "ebp") => Ok(l.imm),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// step 直接吃操作数文本，测试无需构造 Insn。
    fn step(e: &mut Emulator, text: &str) -> bool {
        e.step(text)
    }

    #[test]
    fn test_lea_sp_offset() {
        let mut e = Emulator::new(crate::elf::Arch::X64);
        assert!(e.step("lea rbp,[rsp+0x220]"));
        assert_eq!(e.get_reg("rbp").to_string(), "rsp+0x220");
    }

    #[test]
    fn test_mov_store_and_load() {
        let mut e = Emulator::new(crate::elf::Arch::X64);
        assert!(e.step("mov [rbp-0x48],rsi"));
        assert_eq!(e.get_reg("rbp").to_string(), "rbp");
        // 载入无读回：得到 lambda 本身
        assert!(e.step("mov rdi,[rbp-0x48]"));
        assert_eq!(e.get_reg("rdi").to_string(), "[rbp-0x48]");
    }

    #[test]
    fn test_xor_wide_promotion() {
        // 1.10.0 inst_xor：`xor edx,edx` 写**全名** rdx = 0
        let mut e = Emulator::new(crate::elf::Arch::X64);
        assert!(e.step("xor edx,edx"));
        assert_eq!(e.get_reg("rdx"), Val::Const(0));
        // `xor r12d,r12d`：r12d 不在 ABI 表（与 Ruby check_register! raise 一致）→ fail
        let mut e2 = Emulator::new(crate::elf::Arch::X64);
        assert!(!e2.step("xor r12d,r12d"));
    }

    #[test]
    fn test_lea_rip() {
        let mut e = Emulator::new(crate::elf::Arch::X64);
        assert!(e.step("lea rdi,[rip+0x187c2e]"));
        assert_eq!(e.get_reg("rdi").to_string(), "rip+0x187c2e");
    }

    #[test]
    fn test_push_and_terminal_call() {
        let mut e = Emulator::new(crate::elf::Arch::X64);
        assert!(e.step("push rax"));
        assert_eq!(e.get_reg("rsp").to_string(), "rsp-0x8");
        // terminal call
        assert!(!e.step("call 113010 <posix_spawn@@GLIBC_2.15>"));
        assert_eq!(e.terminal_call.as_deref(), Some("113010 <posix_spawn@@GLIBC_2.15>"));
    }

    #[test]
    fn test_movaps_alignment() {
        let mut e = Emulator::new(crate::elf::Arch::X64);
        assert!(e.step("movaps [rsp+0x60],xmm0"));
        assert_eq!(e.constraints_snapshot().len(), 1);
        // off=0x60 → 0x10-0x60 & 0xf = 0x10-0 → 0
        match e.constraints_snapshot()[0] {
            Constraint::Raw(ref s) => assert_eq!(s, "rsp & 0xf == 0"),
            _ => panic!("expected raw"),
        }
    }

    /// 回归：2.27 e5551 `mov [rcx+0x10],0x0`（rcx=[rbp-0x78]）。
    /// Ruby 把 dst 折叠成 `[[rbp-0x78]+0x10]`，`dst.evaluate` 对嵌套 obj
    /// raise → 模拟停止 → 不产出 e553d gadget。这里必须同样 Fail。
    #[test]
    fn test_mov_store_nested_base_fails() {
        let mut e = Emulator::new(crate::elf::Arch::X64);
        // e553d: mov rcx,[rbp-0x78]
        assert!(e.step("mov rcx,[rbp-0x78]"));
        // e5551: mov [rcx+0x10],0x0 —— dst 折叠为 [[rbp-0x78]+0x10]，evaluate raise
        assert!(!e.step("mov [rcx+0x10],0x0"));
        // 对照：直接栈基不受影响（[[rbp-0x78]+0x10] 之外的正常 store 继续工作）
        let mut e2 = Emulator::new(crate::elf::Arch::X64);
        assert!(e2.step("mov [rbp-0x48],rax"));
        assert!(e2.step("mov rax,[rbp-0x58]"));
        assert!(e2.step("mov [rbp-0x40],rax"));
    }
}
