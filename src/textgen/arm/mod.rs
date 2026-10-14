//! arm（A32/Thumb-2）textgen：objdump 兼容反汇编行（binutils arm-dis.c 移植）。
//!
//! 策略：把 binutils 的指令表（value/mask/format 三元组）机械转录为 Rust 表
//! （`tables`，/tmp/gen_arm_tables.py 生成，iwmmxt 段剔除），再实现 arm-dis.c 的
//! format-string 打印机（`%`-code 解释器）。渲染从**原始编码位**出发，与 yaxpeax
//! 无关 —— yaxpeax Display 无法表达 objdump 的 .w/.n 后缀、imm 阈值注释、
//! literal 注释、adr 改写、sl/fp/ip 寄存器名。
//!
//! GT 校验（/tmp/arm_gt，9 样本全量行流，brew binutils 2.45.1 objdump 输出）。
//! A32 岛（memset/memmove/__aeabi*）从不与窗口重叠（实测 9 样本 0 条 A32 行），
//! 仍实现基本 A32 路径兜底。
//!
//! 关键格式规则（arm-dis.c）：
//! - imm 十进制 + `value_in_comment > 32 || < -16` → `\t@ 0x{v:x}`（64 位补码）
//! - 寄存器偏移路径 value_in_comment=0（永不注释）；literal 路径同样清零
//! - thumb16 `ldr rX, [pc, #imm]` → `@ (lit <sym>)`；thumb32/coproc → `@ <sym>`
//! - thumb16 `add rX, pc, #imm` → `@ (adr rX, dst <sym>)`
//! - 分支目标 `{addr:x} <sym>`（print_address_func → nearest_symbol）
//! - IT 块：`ifthen_state` 顺序状态机（%I 覆写 next；`(state&0xf)==8 → 0`）

mod tables;

use crate::elf::Libc;

/// objdump 寄存器名（arm_regnames[2]：r10=sl r11=fp r12=ip）。
const REG: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl", "fp", "ip", "sp", "lr", "pc",
];

/// arm_conditional（17 项：16 = COND_UNCOND → ""）。
const COND17: [&str; 17] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "<und>",
    "",
];

/// 单条指令解码产物。
pub struct Line {
    pub text: String,
    /// 字节长度（thumb 2/4；A32 4）。
    pub size: u32,
    /// 程序流（分支/调用/间接跳转目标）。
    pub flow: Option<Flow>,
}

pub enum Flow {
    /// 条件/无条件分支（b{cond}、cbz/cbnz）。
    Branch(u64),
    /// 调用（bl/blx imm）。
    Call(u64),
    /// 间接跳转（bx rM / blx rM / tbb / tbh / pop {pc} / ldm {pc}）。
    Indirect,
}

/// 反汇编 [lo, hi)（单 ISA piece）。thumb piece 全 force-thumb；跨 hi 的
/// thumb 宽指令输出 out-of-bounds 标记后停止（objdump piece 语义）。
pub fn disassemble_range(libc: &Libc, lo: u64, hi: u64) -> Vec<Line> {
    if libc.arm_thumb_at(lo) {
        thumb_walk(libc, lo, hi)
    } else {
        a32_walk(libc, lo, hi)
    }
}

/// arm-dis.c find_ifthen_state：从 pc 向后扫 ≤4 条指令找 IT（窗口起点可能
/// 落在 IT 块内）。符号边界立即终止。
fn find_ifthen_state(libc: &Libc, pc: u64) -> u32 {
    let mut addr = pc;
    let mut count: u32 = 1;
    let mut seen_it: u32 = 0;
    let mut it_count: u32 = 0;
    loop {
        let sym_at = libc.arm_sym_starts.binary_search(&addr).is_ok();
        if addr == 0 || sym_at {
            if seen_it != 0 && count & 1 == 1 {
                break;
            }
            return 0;
        }
        addr -= 2;
        let Some(b) = libc.bytes_at_vaddr(addr, 2) else { return 0 };
        let insn = u16::from_le_bytes([b[0], b[1]]) as u32;
        if seen_it != 0 && (insn & 0xf800) < 0xe800 {
            // addr+2 是指令边界
            if count & 1 == 1 {
                break;
            }
            seen_it = 0;
        }
        if (insn & 0xff00) == 0xbf00 && insn & 0xf != 0 && libc.arm_thumb_at(addr) {
            seen_it = insn;
            it_count = count >> 1;
        }
        if (insn & 0xf800) >= 0xe800 {
            count += 1;
        } else {
            count = (count + 2) | 1;
        }
        if count >= 8 && seen_it == 0 {
            return 0;
        }
    }
    let state = (seen_it & 0xe0) | ((seen_it << it_count) & 0x1f);
    if state & 0xf == 0 {
        0
    } else {
        state
    }
}

fn thumb_walk(libc: &Libc, lo: u64, hi: u64) -> Vec<Line> {
    let mut out = Vec::new();
    let mut addr = lo;
    // IT 状态机（arm-dis.c ifthen_state/ifthen_next_state 的顺序等价物）；
    // 起点 = piece/窗口边界：符号处等价 0，否则向后扫（块内进入）
    let mut it_state: u32 = find_ifthen_state(libc, lo);
    let mut it_next: u32 = 0;
    while addr < hi {
        // objdump 的零字节省略（objdump.c disassemble_bytes：skip_zeroes=8 /
        // skip_zeroes_at_end=3，跳过量向下取整到 4 字节）。跳过点之后 IT 状态
        // 清零（find_ifthen_state 回扫跨不过 >=8 字节零区）。
        if let Some(n) = zero_run_skip(libc, addr, hi) {
            addr += n;
            it_state = 0;
            continue;
        }
        let Some(b2) = libc.bytes_at_vaddr(addr, 2) else { break };
        let hw0 = u16::from_le_bytes([b2[0], b2[1]]) as u32;
        let wide = hw0 >> 11 >= 0x1d;
        let take = if wide { 4u64 } else { 2 };
        // 符号范围端点（objdump 的 stop_offset）：宽指令读越界 → OOB 标记并终止
        // 该范围，从下一符号起点继续（objdump 逐符号循环语义）
        let sym_end = match libc.arm_sym_starts.partition_point(|&a| a <= addr) {
            i if i < libc.arm_sym_starts.len() => libc.arm_sym_starts[i].min(hi),
            _ => hi,
        };
        if wide && sym_end - addr < 4 {
            out.push(mk(addr, format!("Address 0x{addr:x} is out of bounds."), 4, None));
            match libc.arm_sym_starts.partition_point(|&a| a <= addr) {
                i if i < libc.arm_sym_starts.len() && libc.arm_sym_starts[i] < hi => {
                    addr = libc.arm_sym_starts[i];
                    it_state = 0;
                    continue;
                }
                _ => break,
            }
        }
        if wide && hi - addr < 4 {
            out.push(mk(addr, format!("Address 0x{addr:x} is out of bounds."), 4, None));
            break;
        }
        let Some(bytes) = libc.bytes_at_vaddr(addr, take as usize) else { break };
        let hw1 = if wide {
            u16::from_le_bytes([bytes[2], bytes[3]]) as u32
        } else {
            0
        };
        // 步骤 1（print_insnLittleARM）：进入指令时按当前状态推 next
        it_next = if it_state != 0 && it_state & 0xf != 8 {
            (it_state & 0xe0) | ((it_state & 0xf) << 1)
        } else {
            0
        };
        let mut ctx = Ctx {
            libc,
            pc: addr,
            given: if wide { (hw0 << 16) | hw1 } else { hw0 },
            printer: if wide { Printer::Thumb32 } else { Printer::Thumb16 },
            vic: 0,
            branch_target: None,
            indirect: false,
            unpred: false,
            it_state,
            it_next,
            cp_num: 0,
            coproc_cond: 16,
            u_reg: 16,
            neon_reject: false,
        };
        let rendered = if wide {
            ctx.cp_num = (ctx.given >> 8) & 0xf;
            ctx.coproc_cond = if it_state != 0 { ((it_state >> 4) & 0xf) as u16 } else { 16 };
            match coproc_match(&mut ctx) {
                Some(t) => Some(t),
                None => match neon_match(&mut ctx) {
                    Some(t) => Some(t),
                    // neon 未命中：printer 复位后再走 THUMB32 表
                    None => {
                        ctx.printer = Printer::Thumb32;
                        try_tables(&mut ctx, &[tables::THUMB32])
                    }
                },
            }
        } else {
            try_tables(&mut ctx, &[tables::THUMB16])
        };
        let text = match rendered {
            Some(mut t) => {
                if ctx.vic > 32 || ctx.vic < -16 {
                    // coproc 打印器显式 & 0xffffffff（arm-dis.c）；thumb 路径为
                    // LP64 补码宽打印（负值罕见，实测窗口内无 thumb 负 vic 行）
                    let v = if ctx.printer == Printer::Coproc {
                        ctx.vic as u32 as u64
                    } else {
                        ctx.vic as u64
                    };
                    t.push_str(&format!("\t@ 0x{v:x}"));
                }
                if ctx.unpred {
                    t.push_str("\t@ <UNPREDICTABLE>");
                }
                t
            }
            None => format!("\t\t@ <UNDEFINED> instruction: 0x{given:0width$x}", given = ctx.given, width = if wide { 8 } else { 4 }),
        };
        let flow = extract_flow(&ctx, &text);
        out.push(mk(addr, text, take as u32, flow));
        // 步骤 3：渲染后 state ← next（%I 渲染中可能已覆写）
        it_state = ctx.it_next;
        addr += take;
    }
    out
}

/// objdump 零字节省略（objdump.c disassemble_bytes）：返回应跳过的字节数。
/// 规则（DEFAULT_SKIP_ZEROES=8 / DEFAULT_SKIP_ZEROES_AT_END=3）：
/// - 连续零字节 >= 8 → 跳 `zeros & !3`（且后随非零时才取整）
/// - 零字节恰好延展到**符号范围端点**且 < 3 → 全跳
/// "端点" = 下一个 dynsym 函数起点与 hi 的较小者（objdump 的 stop_offset）。
fn zero_run_skip(libc: &Libc, addr: u64, hi: u64) -> Option<u64> {
    let sym_end = match libc.arm_sym_starts.partition_point(|&a| a <= addr) {
        i if i < libc.arm_sym_starts.len() => libc.arm_sym_starts[i].min(hi),
        _ => hi,
    };
    let rem = sym_end.saturating_sub(addr) as usize;
    let mut zeros = 0usize;
    while zeros < rem {
        match libc.bytes_at_vaddr(addr + zeros as u64, 1) {
            Some(b) if b[0] == 0 => zeros += 1,
            _ => break,
        }
    }
    if zeros >= 8 {
        Some(if zeros != rem { (zeros & !3) as u64 } else { zeros as u64 })
    } else if zeros == rem && zeros < 3 {
        Some(zeros as u64)
    } else {
        None
    }
}

fn mk(addr: u64, body: String, size: u32, flow: Option<Flow>) -> Line {
    Line { text: format!("{addr:x}:\t{body}"), size, flow }
}

fn sym(libc: &Libc, addr: u64) -> String {
    let addr = addr & 0xffff_ffff; // arm 32 位地址回绕（objdump 打印 8 位 hex）
    let name = libc.nearest_symbol(addr);
    if name.is_empty() {
        format!("{addr:x}")
    } else {
        format!("{addr:x} <{name}>")
    }
}

// ---------------------------------------------------------------------------
// % code 解释器（arm-dis.c 三台打印机：thumb16 / thumb32 / coprocessor）
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Printer {
    Thumb16,
    Thumb32,
    Coproc,
    Neon,
}

struct Ctx<'a> {
    libc: &'a Libc,
    pc: u64,
    given: u32,
    printer: Printer,
    /// value_in_comment（行尾 `\t@ 0x..` 阈值注释）。
    vic: i64,
    branch_target: Option<u64>,
    indirect: bool,
    /// @ <UNPREDICTABLE> 标记。
    unpred: bool,
    /// 当前指令 IT 条件状态（0 = 块外；块内 = cond<<4 | mask 残余）。
    it_state: u32,
    /// 下一指令状态（%I 渲染 IT 指令时覆写）。
    it_next: u32,
    /// coproc 编号与 cond（thumb：IT cond 或 16=COND_UNCOND）。
    cp_num: u32,
    coproc_cond: u16,
    /// coproc %ru 的 u_reg 跟踪。
    u_reg: u32,
    /// neon 打印器的对齐拒绝（C 的 return false）。
    neon_reject: bool,
}

impl<'a> Ctx<'a> {
    fn field(&self, hi: u32, lo: u32) -> u32 {
        if hi < lo || hi > 31 {
            return 0;
        }
        (self.given >> lo) & ((1u32 << (hi - lo + 1)) - 1)
    }

    fn it_cond(&self) -> usize {
        ((self.it_state >> 4) & 0xf) as usize
    }

    fn target(&mut self, t: u64, out: &mut String) {
        self.branch_target = Some(t);
        let s = sym(self.libc, t);
        out.push_str(&s);
    }
}

fn try_tables(ctx: &mut Ctx, tabs: &[&[(u32, u32, Option<&str>)]]) -> Option<String> {
    for &tab in tabs {
        for &(val, mask, fmt) in tab {
            if ctx.given & mask == val {
                let Some(fmt) = fmt else { return None };
                return Some(interp(ctx, fmt));
            }
        }
    }
    None
}

/// coproc/generic-coproc（thumb：hw0 高 4 位 = 0xe 才尝试）。
fn coproc_match(ctx: &mut Ctx) -> Option<String> {
    // 无 0xe 高位门控：无条件空间（0xf…，mcr2/ldc2/cdp2 等）由 mask|0xf0000000
    // 与 value|0xe0000000 的匹配语义自然裁决（print_insn_coprocessor_1 原样）
    ctx.printer = Printer::Coproc;
    for tab in [tables::COPROC, tables::COPROC_GENERIC] {
        for &(val, mask, fmt) in tab {
            let m = mask | 0xf000_0000;
            let v = val | 0xe000_0000;
            if ctx.given & m != v {
                continue;
            }
            match val {
                // cdp/mcr/mrc/ldc/stc：cp 9/10/11（FP）跳过
                0x0e000000 | 0xfe000000 | 0x0e000010 | 0x0e100010 | 0x0c100000 | 0x0c000000
                    if matches!(ctx.cp_num, 9 | 10 | 11) =>
                {
                    continue;
                }
                // mcr2/mrc2/ldc2/stc2：cp 9/10/11 → UNPREDICTABLE
                0xfe000010 | 0xfe100010 | 0xfc100000 | 0xfc000000 if matches!(ctx.cp_num, 9 | 10 | 11) => {
                    ctx.unpred = true;
                }
                _ => {}
            }
            let Some(fmt) = fmt else { return None };
            return Some(interp(ctx, fmt));
        }
    }
    None
}

/// print_insn_neon（thumb 入口翻译 + 匹配 + 打印；返回 None = 未命中/拒绝）。
fn neon_match(ctx: &mut Ctx) -> Option<String> {
    let g = ctx.given;
    // thumb 编码翻译（arm-dis.c print_insn_neon 入口）
    let given = if g & 0xef00_0000 == 0xef00_0000 {
        let bit28 = g & (1 << 28);
        let mut v = g & 0x00ff_ffff;
        if bit28 != 0 {
            v |= 0xf300_0000;
        } else {
            v |= 0xf200_0000;
        }
        v
    } else if g & 0xff00_0000 == 0xf900_0000 {
        g ^ (0xf900_0000 ^ 0xf400_0000)
    } else if g & 0xff00_0000 == 0xfe00_0000 || g & 0xff00_0000 == 0xfc00_0000 {
        g
    } else if g & 0xff90_0f5f != 0xee80_0b10 {
        // 仅 vdup 例外
        return None;
    } else {
        g
    };
    let saved_given = ctx.given;
    ctx.given = given;
    ctx.printer = Printer::Neon;
    ctx.coproc_cond = if ctx.it_state != 0 { ((ctx.it_state >> 4) & 0xf) as u16 } else { 16 };
    let mut result: Option<String> = None;
    for &(val, mask, fmt) in tables::NEON {
        let mut m = mask;
        let mut v = val;
        if m & 0xf000_0000 == 0 {
            // 高 4 位为 0 的条目是条件指令：thumb 匹配时并入 0xe 高位
            m |= 0xf000_0000;
            v |= 0xe000_0000;
        }
        if ctx.given & m != v {
            continue;
        }
        let Some(fmt) = fmt else { continue };
        ctx.neon_reject = false;
        let t = interp(ctx, fmt);
        if !ctx.neon_reject {
            result = Some(t);
            break;
        }
    }
    if result.is_none() {
        // 未命中/被拒绝：恢复 given 与 printer，交回后续表
        ctx.given = saved_given;
        ctx.printer = Printer::Thumb32;
    }
    result
}

/// arm_decode_bitfield：逗号分隔多段位域，little-endian 拼接。
/// 返回 (value, width)。
fn parse_fields(given: u32, spec: &str) -> (u32, u32) {
    let mut value = 0u32;
    let mut width = 0u32;
    for part in spec.split(',') {
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (
                a.parse::<u32>().unwrap_or(0),
                b.parse::<u32>().unwrap_or(31),
            ),
            None => {
                let n = part.parse::<u32>().unwrap_or(0);
                (n, n)
            }
        };
        if lo > hi || hi > 31 {
            continue;
        }
        let bits = hi - lo + 1;
        let f = (given >> lo) & (((1u64 << bits) - 1) as u32);
        value |= f << width;
        width += bits;
    }
    (value, width)
}

fn interp(ctx: &mut Ctx, fmt: &str) -> String {
    let b = fmt.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            break;
        }
        match b[i] {
            b'%' => {
                out.push('%');
                i += 1;
            }
            b'{' => {
                // %{X:body%}：装饰前缀；body 递归（X: 丢弃）
                let mut j = i + 1;
                while j + 1 < b.len() && !(b[j] == b'%' && b[j + 1] == b'}') {
                    j += 1;
                }
                let inner = &b[i + 1..j.min(b.len())];
                let body = if inner.len() >= 2 && inner[1] == b':' {
                    &inner[2..]
                } else {
                    inner
                };
                out.push_str(&interp(ctx, std::str::from_utf8(body).unwrap_or("")));
                i = (j + 2).min(b.len());
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'-' || b[i] == b',') {
                    i += 1;
                }
                if i >= b.len() {
                    break;
                }
                let spec = std::str::from_utf8(&b[start..i]).unwrap_or("");
                let (val, width) = parse_fields(ctx.given, spec);
                let conv = b[i] as char;
                i += 1;
                emit_field(ctx, val, width, conv, b, &mut i, &mut out);
            }
            c => {
                i += 1;
                emit_bare(ctx, c as char, b, &mut i, &mut out);
            }
        }
    }
    out
}

/// 位域转换码（`%<field>c`）。i 指向 conv 之后的字符（供 '?/`/' 消费选项）。
#[allow(clippy::too_many_arguments)]
fn emit_field(ctx: &mut Ctx, val: u32, width: u32, conv: char, b: &[u8], i: &mut usize, out: &mut String) {
    match (ctx.printer, conv) {
        (_, 'r') => {
            out.push_str(REG[(val & 0xf) as usize]);
            // coproc：%ru —— 跟随的 u 消费（u_reg 不可预测检查）
            if ctx.printer == Printer::Coproc && *i < b.len() && b[*i] == b'u' {
                *i += 1;
                if ctx.u_reg == val {
                    ctx.unpred = true;
                }
                ctx.u_reg = val;
            }
        }
        (Printer::Thumb16, 'd') | (Printer::Thumb32, 'd') | (Printer::Neon, 'd') => {
            out.push_str(&val.to_string());
            ctx.vic = val as i64;
        }
        (Printer::Coproc, 'd') => {
            out.push_str(&val.to_string());
            ctx.vic = val as i64;
        }
        (Printer::Thumb16, 'H') => {
            out.push_str(&(val << 1).to_string());
            ctx.vic = (val << 1) as i64;
        }
        (Printer::Thumb16, 'W') | (Printer::Thumb32, 'W') => {
            out.push_str(&(val << 2).to_string());
            ctx.vic = (val << 2) as i64;
        }
        (Printer::Thumb16, 'a') => {
            // pc 相对 literal：((pc+4)&~3) + val*4
            let lit = ((ctx.pc + 4) & !3) + (val as u64) * 4;
            ctx.vic = 0;
            let s = sym(ctx.libc, lit);
            out.push_str(&s);
        }
        (Printer::Thumb16, 'x') => {
            out.push_str(&format!("0x{val:04x}"));
        }
        (Printer::Thumb32, 'x') | (Printer::Coproc, 'x') => {
            out.push_str(&format!("0x{val:x}"));
        }
        (Printer::Thumb16, 'B') => {
            // 符号扩展自最高位：((v ^ (1<<bitend)) - (1<<bitend))
            let bitend = width.saturating_sub(1);
            let v = ((val as u64) ^ (1u64 << bitend)).wrapping_sub(1u64 << bitend) as i64;
            let t = (ctx.pc as i64 + 4 + v * 2) as u64;
            ctx.vic = 0;
            ctx.target(t, out);
        }
        (Printer::Thumb16, 'c') | (Printer::Thumb32, 'c') => {
            out.push_str(COND17[(val & 0xf) as usize]);
        }
        (Printer::Coproc, 'c') => {
            // vcmp 系列 2 位条件：eq/vs/ge/gt
            match val {
                0 => out.push_str("eq"),
                1 => out.push_str("vs"),
                2 => out.push_str("ge"),
                3 => out.push_str("gt"),
                _ => out.push_str("??"),
            }
        }
        (Printer::Thumb32, 'D') => {
            out.push_str(&(val + 1).to_string());
            ctx.vic = val as i64 + 1;
        }
        (Printer::Coproc, 'D') => {
            out.push_str(&format!("d{val}"));
        }
        (Printer::Neon, 'D') => {
            out.push_str(&format!("d{val}"));
        }
        (Printer::Neon, 'Q') => {
            if val & 1 != 0 {
                out.push_str(&format!("<illegal reg q{}.5>", val >> 1));
            } else {
                out.push_str(&format!("q{}", val >> 1));
            }
        }
        (Printer::Neon, 'R') => {
            if ctx.given & (1 << 6) != 0 {
                if val & 1 != 0 {
                    out.push_str(&format!("<illegal reg q{}.5>", val >> 1));
                } else {
                    out.push_str(&format!("q{}", val >> 1));
                }
            } else {
                out.push_str(&format!("d{val}"));
            }
        }
        (Printer::Coproc, 'V') => {
            if ctx.given & (1 << 6) != 0 {
                if val & 1 != 0 {
                    out.push_str(&format!("<illegal reg q{}.5>", val >> 1));
                } else {
                    out.push_str(&format!("q{}", val >> 1));
                }
            } else {
                out.push_str(&format!("d{val}"));
            }
        }
        (Printer::Coproc, 'Q') => {
            if val & 1 != 0 {
                out.push_str(&format!("<illegal reg q{}.5>", val >> 1));
            } else {
                out.push_str(&format!("q{}", val >> 1));
            }
        }
        (Printer::Coproc, 'E') => {
            // 8 位立即数 → 浮点注释（arm-dis.c coproc digit-E）
            let fv: u32 = ((val & 0x80) << 24)
                | ((val & 0x3f) << 19)
                | (if val & 0x40 != 0 { 0xf8 << 22 } else { 1 << 30 });
            let exp = ((fv >> 23) & 0xff) as i32;
            let dec: u64 = if exp >= 124 {
                (78125u64 << (exp - 124)) * (16 + (val & 0xf) as u64)
            } else {
                0
            };
            let (fracw, unit) = if dec % 1_000_000 == 0 {
                (6, dec)
            } else if dec % 10_000 == 0 {
                (3, dec)
            } else {
                (0, dec)
            };
            out.push_str(&val.to_string());
            out.push_str(&format!(
                "\t@ 0x{fv:08x} {}{}.{:0w$}",
                if val & 0x80 != 0 { '-' } else { ' ' },
                dec / 10_000_000,
                (dec % 10_000_000) / 10u64.pow(fracw),
                w = fracw as usize,
            ));
            let _ = unit;
        }
        (Printer::Coproc, 'k') => {
            let from = if ctx.given & (1 << 7) != 0 { 32 } else { 16 };
            out.push_str(&(from - val).to_string());
        }
        (Printer::Thumb32, 'R') | (Printer::Coproc, 'R') => {
            out.push_str(REG[(val & 0xf) as usize]);
            if val == 15 {
                ctx.unpred = true;
            }
            // coproc：%Ru —— 跟随的 u 同样消费（mrrc2 等）
            if ctx.printer == Printer::Coproc && *i < b.len() && b[*i] == b'u' {
                *i += 1;
                if ctx.u_reg == val {
                    ctx.unpred = true;
                }
                ctx.u_reg = val;
            }
        }
        (Printer::Thumb32, 'S') => {
            out.push_str(REG[(val & 0xf) as usize]);
            if val == 13 || val == 15 {
                ctx.unpred = true;
            }
        }
        (Printer::Thumb32, 's') => {
            // MVE 向量宽度名（glibc 不出现；兜底）
            out.push_str(match val {
                0 => "8",
                1 => "16",
                2 => "32",
                3 => "64",
                _ => "<undef size>",
            });
        }
        (Printer::Neon, 'e') => {
            out.push_str(&((1u64 << width.min(32)).wrapping_sub(val as u64).to_string()));
        }
        (Printer::Neon, 'S') | (Printer::Neon, 'T') | (Printer::Neon, 'U') => {
            // 宽度编码：base = 8 << (c - 'S')；后随 limit 十六进制字符
            let base: u32 = 8 << (conv as u8 - b'S');
            let limit_ch = b.get(*i).map(|c| *c as char).unwrap_or('0');
            *i += 1;
            let limit = limit_ch.to_digit(16).unwrap_or(0);
            let (low, high) = (limit >> 2, limit & 3);
            if val < low || val > high {
                out.push_str(&format!("<illegal width {}>", base << val));
            } else {
                out.push_str(&(base << val).to_string());
            }
        }
        (Printer::Neon, '`') => {
            if val == 0 && *i < b.len() {
                out.push(b[*i] as char);
            }
            *i += 1;
        }
        (Printer::Neon, '\'') => {
            if val == ((1u64 << width.min(32)) - 1) as u32 && *i < b.len() {
                out.push(b[*i] as char);
            }
            *i += 1;
        }
        (_, '\'') => {
            // 位域全 1（thumb16 单 bit：≠0）→ 输出下一字符
            let on = if ctx.printer == Printer::Thumb16 {
                val != 0
            } else {
                val == (((1u64 << width) - 1) as u32)
            };
            if on && *i < b.len() {
                out.push(b[*i] as char);
            }
            *i += 1;
        }
        (_, '`') => {
            // 位域全 0 → 输出下一字符
            if val == 0 && *i < b.len() {
                out.push(b[*i] as char);
            }
            *i += 1;
        }
        (_, '?') => {
            if ctx.printer == Printer::Thumb16 {
                // 单 bit：置位取第一字符，否则第二
                let c = if val != 0 { b.get(*i).copied() } else { b.get(*i + 1).copied() };
                if let Some(c) = c {
                    out.push(c as char);
                }
                *i += 2;
            } else {
                // 大端选项表：C 的 c[(1<<width)-val]（c 指向 '?' 本身）；
                // 本解释器 i 已越过 '?' → 等价 b[i + (1<<width) - val - 1]
                let n = (1u32 << width.min(4)) as usize;
                let idx = n.saturating_sub(val as usize + 1);
                if let Some(c) = b.get(*i + idx) {
                    out.push(*c as char);
                }
                *i += n;
            }
        }
        _ => out.push('?'),
    }
}

/// 裸转换码（`%c` 无位域）。i 指向 conv 之后（供 y/z 消费子类型）。
fn emit_bare(ctx: &mut Ctx, conv: char, b: &[u8], i: &mut usize, out: &mut String) {
    let g = ctx.given;
    match (ctx.printer, conv) {
        // ---- thumb16 / thumb32 共通（IT 条件） ----
        (_, 'c') if ctx.printer != Printer::Coproc => {
            if ctx.it_state != 0 {
                out.push_str(COND17[ctx.it_cond()]);
            }
        }
        (Printer::Neon, 'u') => {
            if ctx.it_state != 0 {
                ctx.unpred = true;
            }
            out.push_str(COND17[ctx.coproc_cond as usize]);
        }
        (Printer::Neon, 'c') => {
            out.push_str(COND17[ctx.coproc_cond as usize]);
        }
        (Printer::Coproc, 'u') => {
            if ctx.coproc_cond != 16 {
                ctx.unpred = true;
            }
            out.push_str(COND17[ctx.coproc_cond as usize]);
        }
        (Printer::Coproc, 'c') => {
            if ctx.coproc_cond != 16 && ctx.cp_num == 9 {
                ctx.unpred = true;
            }
            out.push_str(COND17[ctx.coproc_cond as usize]);
        }
        (Printer::Coproc, 'b') => {
            out.push_str(COND17[ctx.coproc_cond as usize]);
        }
        (Printer::Thumb16, 'C') => {
            if ctx.it_state != 0 {
                out.push_str(COND17[ctx.it_cond()]);
            } else {
                out.push('s');
            }
        }
        (Printer::Thumb16, 'I') => {
            // IT 后缀 + 操作数；覆写 ifthen_next_state
            ctx.it_next = g & 0xff;
            let mut tmp = g << 1;
            while tmp & 0xf != 0 {
                out.push(if (g ^ tmp) & 0x10 != 0 { 'e' } else { 't' });
                tmp <<= 1;
            }
            out.push('\t');
            out.push_str(COND17[((g >> 4) & 0xf) as usize]);
        }
        (_, 'x') if ctx.printer != Printer::Coproc => {
            if ctx.it_next != 0 {
                out.push_str("\t@ unpredictable branch in IT block\n");
            }
        }
        (_, 'X') if ctx.printer != Printer::Coproc => {
            if ctx.it_state != 0 {
                out.push_str(&format!("\t@ unpredictable <IT:{}>", COND17[ctx.it_cond()]));
            }
        }
        // ---- thumb16 专用 ----
        (Printer::Thumb16, 'S') => {
            let mut reg = (g >> 3) & 0x7;
            if g & (1 << 6) != 0 {
                reg += 8;
            }
            out.push_str(REG[reg as usize]);
        }
        (Printer::Thumb16, 'D') => {
            let mut reg = g & 0x7;
            if g & (1 << 7) != 0 {
                reg += 8;
            }
            out.push_str(REG[reg as usize]);
        }
        (Printer::Thumb16, 'M') => out.push_str(&reglist16(g, false, false)),
        (Printer::Thumb16, 'N') => out.push_str(&reglist16(g, true, false)),
        (Printer::Thumb16, 'O') => out.push_str(&reglist16(g, false, true)),
        (Printer::Thumb16, 'W') => {
            // LDMIA writeback：基址寄存器不在掩码中
            if g & (1 << ((g & 0x0700) >> 8)) == 0 {
                out.push('!');
            }
        }
        (Printer::Thumb16, 'b') => {
            // CZB 目标：pc+4 + i5
            let t = ctx.pc + 4 + (((g & 0xf8) >> 2) + ((g & 0x200) >> 3)) as u64;
            ctx.target(t, out);
        }
        (Printer::Thumb16, 's') => {
            let mut imm = (g & 0x7c0) >> 6;
            if imm == 0 {
                imm = 32;
            }
            out.push_str(&format!("#{imm}"));
        }
        // ---- thumb32 专用 ----
        (Printer::Thumb32, 'I') => {
            let imm = (g & 0xff) | ((g & 0x7000) >> 4) | ((g & 0x0400_0000) >> 15);
            out.push_str(&format!("#{imm}"));
            ctx.vic = imm as i64;
        }
        (Printer::Thumb32, 'M') => {
            let imm = thumb_expand_imm((g & 0xff) | ((g & 0x7000) >> 4) | ((g & 0x0400_0000) >> 15));
            out.push_str(&format!("#{imm}"));
            ctx.vic = imm as i64;
        }
        (Printer::Thumb32, 'J') => {
            let imm = (g & 0xff) | ((g & 0x7000) >> 4) | ((g & 0x0400_0000) >> 15) | ((g & 0x000f_0000) >> 4);
            out.push_str(&format!("#{imm}"));
            ctx.vic = imm as i64;
        }
        (Printer::Thumb32, 'K') => {
            let imm = ((g & 0x000f_0000) >> 16) | (g & 0xff0) | ((g & 0xf) << 12);
            out.push_str(&format!("#{imm}"));
            ctx.vic = imm as i64;
        }
        (Printer::Thumb32, 'H') => {
            let imm = ((g & 0x000f_0000) >> 4) | (g & 0xfff);
            out.push_str(&format!("#{imm}"));
            ctx.vic = imm as i64;
        }
        (Printer::Thumb32, 'V') => {
            let imm = (g & 0xfff) | ((g & 0x000f_0000) >> 4);
            out.push_str(&format!("#{imm}"));
            ctx.vic = imm as i64;
        }
        (Printer::Thumb32, 'S') => {
            // 可能带移位的 Rm
            let reg = (g & 0xf) as usize;
            let stp = (g & 0x30) >> 4;
            let mut imm = ((g & 0xc0) >> 6) | ((g & 0x7000) >> 10);
            out.push_str(REG[reg]);
            match stp {
                0 => {
                    if imm > 0 {
                        out.push_str(&format!(", lsl #{imm}"));
                    }
                }
                1 => {
                    if imm == 0 {
                        imm = 32;
                    }
                    out.push_str(&format!(", lsr #{imm}"));
                }
                2 => {
                    if imm == 0 {
                        imm = 32;
                    }
                    out.push_str(&format!(", asr #{imm}"));
                }
                _ => {
                    if imm == 0 {
                        out.push_str(", rrx");
                    } else {
                        out.push_str(&format!(", ror #{imm}"));
                    }
                }
            }
        }
        (Printer::Thumb32, 's') => {
            // SSAT 移位字段
            let shift = ((g & 0xc0) >> 6) | ((g & 0x7000) >> 10);
            if g & (1 << 21) != 0 {
                out.push_str(&format!(", asr #{shift}"));
            } else if shift != 0 {
                out.push_str(&format!(", lsl #{shift}"));
            }
        }
        (Printer::Thumb32, 'R') => {
            let rot = (g & 0x30) >> 4;
            if rot != 0 {
                out.push_str(&format!(", ror #{}", rot * 8));
            }
        }
        (Printer::Thumb32, 'U') => {
            if g & 0xf0 == 0x60 {
                match g & 0xf {
                    0xf => out.push_str("sy"),
                    n => out.push_str(&format!("#{n}")),
                }
            } else if let Some(o) = data_barrier_option(g & 0xf) {
                out.push_str(o);
            } else {
                out.push_str(&format!("#{}", g & 0xf));
            }
        }
        (Printer::Thumb32, 'E') => {
            let lsb = ((g & 0xc0) >> 6) | ((g & 0x7000) >> 10);
            let msb = g & 0x1f;
            out.push_str(&format!("#{lsb}, #{}", msb as i32 - lsb as i32 + 1));
        }
        (Printer::Thumb32, 'F') => {
            let lsb = ((g & 0xc0) >> 6) | ((g & 0x7000) >> 10);
            out.push_str(&format!("#{lsb}, #{}", (g & 0x1f) + 1));
        }
        (Printer::Thumb32, 'G') => {
            let boff = ((g & 0x0780_0000) >> 23) << 1;
            out.push_str(&format!("{boff:x}"));
        }
        (Printer::Thumb32, 'b') => {
            // Bcc.W（I1/I2 不做 XOR —— arm-dis.c case 'b' 原样）
            let s = (g >> 26) & 1;
            let j1 = (g >> 13) & 1;
            let j2 = (g >> 11) & 1;
            let mut off: u64 = 0;
            off |= (((s == 0) as u64) << 20);
            off |= (j2 as u64) << 19;
            off |= (j1 as u64) << 18;
            off |= ((g & 0x003f_0000) as u64) >> 4;
            off |= ((g & 0x7ff) as u64) << 1;
            let off = (off as i64).wrapping_sub(1 << 20);
            let t = (ctx.pc as i64 + 4 + off) as u64;
            ctx.target(t, out);
        }
        (Printer::Thumb32, 'B') => {
            // B.W / BL / BLX（I1 = !(J1^S)，I2 = !(J2^S)）
            let s = (g >> 26) & 1;
            let i1 = (g >> 13) & 1;
            let i2 = (g >> 11) & 1;
            let mut off: u64 = 0;
            off |= (((s == 0) as u64) << 24);
            off |= (((!(i1 ^ s)) & 1) as u64) << 23;
            off |= (((!(i2 ^ s)) & 1) as u64) << 22;
            off |= ((g & 0x03ff_0000) as u64) >> 4;
            off |= ((g & 0x7ff) as u64) << 1;
            let mut t = off.wrapping_sub(1 << 24).wrapping_add(ctx.pc + 4);
            // BLX 目标字对齐
            if g & 0x1000 == 0 {
                t &= !2;
            }
            ctx.target(t, out);
        }
        (Printer::Thumb32, 'W') => {
            let imm_a = (g & 0x001f_0000) >> 16;
            let imm_b = (g & 0x0000_07fe) >> 1;
            let imm_c = (g & 0x0000_0800) >> 11;
            let mut off = (imm_a as u64) << 12 | (imm_b as u64) << 2 | (imm_c as u64) << 1;
            if off & 0x10000 != 0 {
                off = off.wrapping_sub(1 << 17);
            }
            let t = ctx.pc + 4 + off;
            ctx.target(t, out);
        }
        (Printer::Thumb32, 'Y') => {
            let imm_a = (g & 0x007f_0000) >> 16;
            let imm_b = (g & 0x0000_07fe) >> 1;
            let imm_c = (g & 0x0000_0800) >> 11;
            let mut off = (imm_a as u64) << 12 | (imm_b as u64) << 2 | (imm_c as u64) << 1;
            if off & 0x40000 != 0 {
                off = off.wrapping_sub(1 << 19);
            }
            let t = ctx.pc + 4 + off;
            ctx.target(t, out);
        }
        (Printer::Thumb32, 'Z') => {
            let imm_a = (g & 0x0001_0000) >> 16;
            let imm_b = (g & 0x0000_07fe) >> 1;
            let imm_c = (g & 0x0000_0800) >> 11;
            let mut off = (imm_a as u64) << 12 | (imm_b as u64) << 2 | (imm_c as u64) << 1;
            if off & 0x1000 != 0 {
                off = off.wrapping_sub(1 << 13);
            }
            let t = ctx.pc + 4 + off;
            ctx.target(t, out);
            let t2 = (g & 0x0002_0000) >> 17;
            let endoff = ((g & 0x0780_0000) >> 23) << 1;
            let boff = if t2 == 1 { 4 } else { 2 };
            out.push_str(&format!(", {:x}", endoff + boff));
        }
        (Printer::Thumb32, 'Q') => {
            let immh = (g & 0x0000_07fe) >> 1;
            let imml = (g & 0x0000_0800) >> 11;
            let off = (immh as u64) << 2 | (imml as u64) << 1;
            let t = ctx.pc + 4 + off;
            ctx.target(t, out);
        }
        (Printer::Thumb32, 'P') => {
            let immh = (g & 0x0000_07fe) >> 1;
            let imml = (g & 0x0000_0800) >> 11;
            let off = (immh as u64) << 2 | (imml as u64) << 1;
            let t = (ctx.pc + 4).wrapping_sub(off);
            ctx.target(t, out);
        }
        (Printer::Thumb32, 'L') => {
            // ldrd/strd 的 pc 相对注释
            if (g >> 16) & 0xf == 0xf {
                let mut off = ((g & 0xff) * 4) as i64;
                if g & (1 << 23) == 0 {
                    off = -off;
                }
                out.push_str("\t@ ");
                let lit = ((ctx.pc & !3) + 4).wrapping_add(off as u64);
                let s = sym(ctx.libc, lit);
                out.push_str(&s);
            }
        }
        (Printer::Thumb32, 'm') | (Printer::Thumb32, 'n') => {
            let clrm = conv == 'n';
            out.push('{');
            let mut started = false;
            for reg in 0..16usize {
                if g & (1 << reg) == 0 {
                    continue;
                }
                if started {
                    out.push_str(", ");
                }
                started = true;
                if clrm && reg == 13 {
                    out.push_str("(invalid: sp)");
                } else if clrm && reg == 15 {
                    out.push_str("APSR");
                } else {
                    out.push_str(REG[reg]);
                }
            }
            out.push('}');
        }
        (Printer::Thumb32, 'w') => {
            // 核心访存宽度/符号
            let sbit = (g >> 24) & 1;
            let ty = (g >> 21) & 3;
            match ty {
                0 => out.push_str(if sbit != 0 { "sb" } else { "b" }),
                1 => out.push_str(if sbit != 0 { "sh" } else { "h" }),
                2 => {
                    if sbit != 0 {
                        out.push_str("??");
                    }
                }
                _ => out.push_str("??"),
            }
        }
        (Printer::Thumb32, 'a') => {
            let s = thumb32_addr(ctx);
            out.push_str(&s);
        }
        (Printer::Thumb32, 'A') => {
            let u = g & 0x0080_0000 != 0;
            let w = g & 0x0020_0000 != 0;
            let pre = g & 0x0100_0000 != 0;
            let rn = ((g >> 16) & 0xf) as usize;
            let off = (g & 0xff) as u32;
            out.push('[');
            out.push_str(REG[rn]);
            if pre {
                if off != 0 || !u {
                    out.push_str(&format!(", #{}{}", if u { '+' } else { '-' }, off * 4));
                    ctx.vic = (off * 4) as i64 * if u { 1 } else { -1 };
                }
                out.push(']');
                if w {
                    out.push('!');
                }
            } else {
                out.push_str("], ");
                if w {
                    out.push_str(&format!("#{}{}", if u { '+' } else { '-' }, off * 4));
                    ctx.vic = (off * 4) as i64 * if u { 1 } else { -1 };
                } else {
                    out.push_str(&format!("{{{off}}}"));
                    ctx.vic = off as i64;
                }
            }
        }
        (Printer::Thumb32, 'C') => {
            // mrs 的 PSR 字段 / banked
            if g & 0xff == 0 {
                out.push_str(&format!("{}PSR_", if g & 0x100_000 != 0 { 'S' } else { 'C' }));
                if g & 0x800 != 0 { out.push('f'); }
                if g & 0x400 != 0 { out.push('s'); }
                if g & 0x200 != 0 { out.push('x'); }
                if g & 0x100 != 0 { out.push('c'); }
            } else if g & 0x20 != 0 {
                let sysm = ((g & 0xf00) >> 8) | (g & 0x30) | ((g & 0x0010_0000) >> 14);
                out.push_str(&format!("(UNDEF: {sysm})"));
            } else {
                out.push_str(psr_name(g & 0xff));
            }
        }
        (Printer::Thumb32, 'D') => {
            if g & 0xff == 0 || g & 0x20 != 0 {
                let sm = ((g & 0xf0000) >> 16) | (g & 0x30) | ((g & 0x0010_0000) >> 14);
                out.push_str(&format!("(UNDEF: {sm})"));
            } else {
                out.push_str(psr_name(g & 0xff));
            }
        }
        // ---- coproc 专用 ----
        (Printer::Coproc, 'A') | (Printer::Coproc, 'K') => {
            let s = coproc_addr(ctx, conv == 'K');
            out.push_str(&s);
        }
        (Printer::Neon, 'A') => {
            // vstm 多寄存器 store 列表
            const ENC: [u8; 16] = [
                0x4, 0x14, 0x4, 0x4, 0x3, 0x13, 0x3, 0x1, 0x2, 0x12, 0x2, 0, 0, 0, 0, 0,
            ];
            let g = ctx.given;
            let rd = (((g >> 12) & 0xf) | (((g >> 22) & 1) << 4)) as i32;
            let rn = ((g >> 16) & 0xf) as usize;
            let rm = (g & 0xf) as usize;
            let align = (g >> 4) & 0x3;
            let ty = (g >> 8) & 0xf;
            let n = (ENC[ty as usize] & 0xf) as i32;
            let stride = ((ENC[ty as usize] >> 4) + 1) as i32;
            out.push('{');
            if stride > 1 {
                for ix in 0..n {
                    if ix > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!("d{}", rd + ix * stride));
                }
            } else if n == 1 {
                out.push_str(&format!("d{rd}"));
            } else {
                out.push_str(&format!("d{rd}-d{}", rd + n - 1));
            }
            out.push_str("}, [");
            out.push_str(REG[rn]);
            if align != 0 {
                out.push_str(&format!(" :{}", 32 << align));
            }
            out.push(']');
            if rm == 0xd {
                out.push('!');
            } else if rm != 0xf {
                out.push_str(&format!(", {}", REG[rm]));
            }
        }
        (Printer::Neon, 'B') => {
            let g = ctx.given;
            let rd = (((g >> 12) & 0xf) | (((g >> 22) & 1) << 4)) as i32;
            let rn = ((g >> 16) & 0xf) as usize;
            let rm = (g & 0xf) as usize;
            let idx_align = (g >> 4) & 0xf;
            let size = (g >> 10) & 0x3;
            let idx = idx_align >> (size + 1);
            let length = ((g >> 8) & 3) + 1;
            let mut stride = 1i32;
            if length > 1 && size > 0 {
                stride = if idx_align & (1 << size) != 0 { 2 } else { 1 };
            }
            let mut align = 0u32;
            match length {
                1 => {
                    let amask = (1u32 << size) - 1;
                    if idx_align & (1 << size) != 0 {
                        ctx.neon_reject = true;
                        return;
                    }
                    if size > 0 {
                        if idx_align & amask == amask {
                            align = 8 << size;
                        } else if idx_align & amask != 0 {
                            ctx.neon_reject = true;
                            return;
                        }
                    }
                }
                2 => {
                    if size == 2 && idx_align & 2 != 0 {
                        ctx.neon_reject = true;
                        return;
                    }
                    align = if idx_align & 1 != 0 { 16 << size } else { 0 };
                }
                3 => {
                    if (size == 2 && idx_align & 3 != 0) || idx_align & 1 != 0 {
                        ctx.neon_reject = true;
                        return;
                    }
                }
                _ => {
                    if size == 2 {
                        if idx_align & 3 == 3 {
                            ctx.neon_reject = true;
                            return;
                        }
                        align = (idx_align & 3) * 64;
                    } else {
                        align = if idx_align & 1 != 0 { 32 << size } else { 0 };
                    }
                }
            }
            out.push('{');
            for i in 0..length {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&format!("d{}[{}]", rd + i as i32 * stride, idx));
            }
            out.push_str("}, [");
            out.push_str(REG[rn]);
            if align != 0 {
                out.push_str(&format!(" :{align}"));
            }
            out.push(']');
            if rm == 0xd {
                out.push('!');
            } else if rm != 0xf {
                out.push_str(&format!(", {}", REG[rm]));
            }
        }
        (Printer::Neon, 'C') => {
            let g = ctx.given;
            let rd = (((g >> 12) & 0xf) | (((g >> 22) & 1) << 4)) as i32;
            let rn = ((g >> 16) & 0xf) as usize;
            let rm = (g & 0xf) as usize;
            let align = (g >> 4) & 0x1;
            let size = (g >> 6) & 0x3;
            let ty = (g >> 8) & 0x3;
            let mut n = ty as i32 + 1;
            let mut stride = ((g >> 5) & 0x1) as i32;
            if stride != 0 && n == 1 {
                n += 1;
            } else {
                stride += 1;
            }
            out.push('{');
            if stride > 1 {
                for ix in 0..n {
                    if ix > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!("d{}[]", rd + ix * stride));
                }
            } else if n == 1 {
                out.push_str(&format!("d{rd}[]"));
            } else {
                out.push_str(&format!("d{rd}[]-d{}[]", rd + n - 1));
            }
            out.push_str("}, [");
            out.push_str(REG[rn]);
            if align != 0 {
                let mut a = (8 * (ty as u32 + 1)) << size;
                if ty == 3 {
                    a = if size > 1 { a >> 1 } else { a };
                }
                if ty == 2 || (ty == 0 && size == 0) {
                    out.push_str(&format!(" :<bad align {a}>"));
                } else {
                    out.push_str(&format!(" :{a}"));
                }
            }
            out.push(']');
            if rm == 0xd {
                out.push('!');
            } else if rm != 0xf {
                out.push_str(&format!(", {}", REG[rm]));
            }
        }
        (Printer::Neon, 'D') => {
            let g = ctx.given;
            let raw_reg = ((g & 0xf) | ((g >> 1) & 0x10)) as u32;
            let size = (g >> 20) & 3;
            let reg = raw_reg & ((4 << size) - 1);
            let ix = raw_reg >> size >> 2;
            out.push_str(&format!("d{reg}[{ix}]"));
        }
        (Printer::Neon, 'E') => {
            // Neon 编码常量（vmov/vorr/vbic/mvn）
            let g = ctx.given;
            let mut bits = 0u32;
            bits |= ((g >> 24) & 1) << 7;
            bits |= ((g >> 16) & 7) << 4;
            bits |= g & 15;
            let cmode = (g >> 8) & 0xf;
            let op = (g >> 5) & 1;
            let (mut value, mut hival): (u64, u64) = (0, 0);
            let size: u32;
            let mut isfloat = false;
            if cmode < 8 {
                let shift = (cmode >> 1) & 3;
                value = (bits as u64) << (8 * shift);
                size = 32;
            } else if cmode < 12 {
                let shift = (cmode >> 1) & 1;
                value = (bits as u64) << (8 * shift);
                size = 16;
            } else if cmode < 14 {
                let shift = (cmode & 1) + 1;
                value = (bits as u64) << (8 * shift);
                value |= (1u64 << (8 * shift)) - 1;
                size = 32;
            } else if cmode == 14 {
                if op != 0 {
                    for ix in (0..8).rev() {
                        let mask: u64 = if bits >> ix & 1 != 0 { 0xff } else { 0 };
                        if ix <= 3 {
                            value = (value << 8) | mask;
                        } else {
                            hival = (hival << 8) | mask;
                        }
                    }
                    size = 64;
                } else {
                    value = bits as u64;
                    size = 8;
                }
            } else if op == 0 {
                value = ((bits & 0x7f) as u64) << 19;
                value |= ((bits & 0x80) as u64) << 24;
                let tmp: u64 = if bits & 0x40 != 0 { 0x3c } else { 0x40 };
                value |= tmp << 24;
                size = 32;
                isfloat = true;
            } else {
                out.push_str(&format!("<illegal constant {bits:.8x}:{cmode:x}:{op:x}>"));
                return;
            }
            match size {
                8 => out.push_str(&format!("#{value}\t@ 0x{value:.2x}")),
                16 => out.push_str(&format!("#{value}\t@ 0x{value:.4x}")),
                32 => {
                    if isfloat {
                        let f = f32::from_bits(value as u32) as f64;
                        out.push_str(&format!("#{}\t@ 0x{value:.8x}", fmt_g(f, 7)));
                    } else {
                        let sv = value as i32;
                        out.push_str(&format!("#{sv}\t@ 0x{value:.8x}"));
                    }
                }
                _ => out.push_str(&format!("#0x{hival:.8x}{value:.8x}")),
            }
        }
        (Printer::Neon, 'F') => {
            let g = ctx.given;
            let regno = (((g >> 16) & 0xf) | ((g >> (7 - 4)) & 0x10)) as i32;
            let num = ((g >> 8) & 0x3) as i32;
            out.push('{');
            if num == 0 {
                out.push_str(&format!("d{regno}"));
            } else if num + regno >= 32 {
                out.push_str(&format!("d{regno}-<overflow reg d{}", regno + num));
            } else {
                out.push_str(&format!("d{regno}-d{}", regno + num));
            }
            out.push('}');
        }
        (Printer::Coproc, 'B') => {
            let regno = (((g >> 12) & 0xf) | ((g >> 18) & 0x10)) as i32;
            let off = ((g >> 1) & 0x3f) as i32;
            out.push('{');
            if off == 1 {
                out.push_str(&format!("d{regno}"));
            } else if regno + off > 32 {
                out.push_str(&format!("d{regno}-<overflow reg d{}>", regno + off - 1));
            } else {
                out.push_str(&format!("d{regno}-d{}", regno + off - 1));
            }
            out.push('}');
        }
        (Printer::Coproc, 'C') => {
            let single = (g >> 8) & 1 == 0;
            let prefix = if single { 's' } else { 'd' };
            let dreg = (g >> 22) & 1;
            let vd = (g >> 12) & 0xf;
            let reg = if single { (vd << 1) | dreg } else { (dreg << 4) | vd } as i32;
            let num = ((g >> if single { 0 } else { 1 }) & 0x7f) as i32;
            let maxreg = if single { 31 } else { 15 };
            out.push('{');
            if num == 0 {
                // 空
            } else if num == 1 {
                out.push_str(&format!("{prefix}{reg}, "));
            } else if reg + num - 1 > maxreg {
                out.push_str(&format!(
                    "{prefix}{reg}-<overflow reg d{}, ",
                    if single { (reg + num - 1) >> 1 } else { reg + num - 1 }
                ));
            } else {
                out.push_str(&format!("{prefix}{reg}-{prefix}{}, ", reg + num - 1));
            }
            out.push_str("VPR}");
        }
        (Printer::Coproc, 'J') => {
            let regno = ((g >> 13) & 0x7) | (((g >> 22) & 1) << 3);
            let name = match regno {
                0x1 => "FPSCR".to_string(),
                0x2 => "FPSCR_nzcvqc".to_string(),
                0xc => "VPR".to_string(),
                0xd => "P0".to_string(),
                0xe => "FPCXTNS".to_string(),
                0xf => "FPCXTS".to_string(),
                _ => format!("<invalid reg {regno}>"),
            };
            out.push_str(&name);
        }
        (Printer::Coproc, 'y') | (Printer::Coproc, 'z') => {
            let single = conv == 'y';
            let sub = b.get(*i).map(|c| *c as char).unwrap_or('0');
            *i += 1;
            let regno: i32 = match sub {
                '4' | '0' => {
                    let mut r = (g & 0xf) as i32;
                    if single {
                        r = (r << 1) + ((g >> 5) & 1) as i32;
                    } else {
                        r += (((g >> 5) & 1) as i32) << 4;
                    }
                    r
                }
                '1' | '3' => {
                    let mut r = ((g >> 12) & 0xf) as i32;
                    if single {
                        r = (r << 1) + ((g >> 22) & 1) as i32;
                    } else {
                        r += (((g >> 22) & 1) as i32) << 4;
                    }
                    r
                }
                '2' => {
                    let mut r = ((g >> 16) & 0xf) as i32;
                    if single {
                        r = (r << 1) + ((g >> 7) & 1) as i32;
                    } else {
                        r += (((g >> 7) & 1) as i32) << 4;
                    }
                    r
                }
                _ => 0,
            };
            let prefix = if single { 's' } else { 'd' };
            if sub == '3' {
                out.push('{');
            }
            out.push_str(&format!("{prefix}{regno}"));
            if sub == '3' {
                let mut count = (g & 0xff) as i32;
                if !single {
                    count >>= 1;
                }
                count -= 1;
                if count != 0 {
                    out.push('-');
                    out.push_str(&format!("{prefix}{}", regno + count));
                }
                out.push('}');
            } else if sub == '4' {
                out.push_str(", ");
                out.push_str(&format!("{prefix}{}", regno + 1));
            }
        }
        (Printer::Coproc, 'L') => match g & 0x0040_0100 {
            0 => out.push('b'),
            0x0040_0000 => out.push('h'),
            0x100 => out.push('w'),
            _ => out.push('d'),
        },
        (Printer::Coproc, 'Z') => {
            let v = ((g >> 16) & 0xf0) | (g & 0xf);
            out.push_str(&v.to_string());
        }
        (Printer::Coproc, 'l') => {
            let rn = ((g >> 16) & 0xf) as usize;
            let mut off = (g & 0xff) as i64;
            let mult: i64 = if g & 0x100 != 0 { 4 } else { 1 };
            let n = g & 0x0080_0000 == 0;
            let p = g & 0x0100_0000 != 0;
            let w = g & 0x0020_0000 != 0;
            out.push('[');
            out.push_str(REG[rn]);
            if mult > 1 {
                ctx.vic = off * mult;
                if n {
                    ctx.vic = -ctx.vic;
                }
            }
            if off != 0 {
                if p {
                    out.push_str(&format!(", #{}{}", if n { "-" } else { "" }, off * mult));
                    out.push_str(if w { "]!" } else { "]" });
                } else {
                    out.push_str(&format!("], #{}{}", if n { "-" } else { "" }, off * mult));
                }
            } else {
                out.push(']');
            }
        }
        (Printer::Coproc, 'r') => {
            // ldc/stc 寄存器偏移形式
            let imm4 = (g >> 4) & 0xf;
            let puw = ((g >> 22) & 6) | ((g >> 21) & 1);
            let u = g & 0x0080_0000 != 0;
            let rm = (g & 0xf) as usize;
            let rn = ((g >> 16) & 0xf) as usize;
            match puw {
                1 | 3 => {
                    out.push_str(&format!("[{}], {}{}", REG[rn], if u { '+' } else { '-' }, REG[rm]));
                    if imm4 != 0 {
                        out.push_str(&format!(", lsl #{imm4}"));
                    }
                }
                4..=7 => {
                    out.push_str(&format!(
                        "[{}, {}{}",
                        REG[rn],
                        if u { '+' } else { '-' },
                        REG[rm]
                    ));
                    if imm4 > 0 {
                        out.push_str(&format!(", lsl #{imm4}"));
                    }
                    out.push(']');
                    if puw == 5 || puw == 7 {
                        out.push('!');
                    }
                }
                _ => out.push_str("INVALID"),
            }
        }
        (Printer::Coproc, 'i') => {
            let imm5 = ((g & 0x100) >> 4) | (g & 0xf);
            let v = if imm5 == 0 { 32 } else { imm5 };
            out.push_str(&v.to_string());
        }
        _ => out.push('?'),
    }
}

/// thumb32 `%a`：普通 load/store 寻址模式。
fn thumb32_addr(ctx: &mut Ctx) -> String {
    let g = ctx.given;
    let mut out = String::new();
    let rn = ((g >> 16) & 0xf) as usize;
    let u = g & 0x0080_0000 != 0;
    let op = (g >> 8) & 0xf;
    let i12 = g & 0xfff;
    let i8 = g & 0xff;
    let mut writeback = false;
    let mut postind = false;
    let mut offset: i64 = 0;
    out.push('[');
    out.push_str(REG[rn]);
    if u {
        // 12 位正立即数偏移
        offset = i12 as i64;
        if rn != 15 {
            ctx.vic = offset;
        }
    } else if rn == 15 {
        // 12 位负立即数（literal）
        offset = -(i12 as i64);
    } else if op == 0 {
        // 移位寄存器偏移
        let rm = (i8 & 0xf) as usize;
        let sh = (i8 & 0x30) >> 4;
        out.push_str(", ");
        out.push_str(REG[rm]);
        if sh != 0 {
            out.push_str(&format!(", lsl #{sh}"));
        }
        out.push(']');
        return out;
    } else {
        match op {
            0xE => offset = i8 as i64,
            0xC => offset = -(i8 as i64),
            0xF => {
                offset = i8 as i64;
                writeback = true;
            }
            0xD => {
                offset = -(i8 as i64);
                writeback = true;
            }
            0xB => {
                offset = i8 as i64;
                postind = true;
            }
            0x9 => {
                offset = -(i8 as i64);
                postind = true;
            }
            _ => {
                out.push_str(", <undefined>]");
                return out;
            }
        }
    }
    if postind {
        out.push_str(&format!("], #{offset}"));
    } else {
        if offset != 0 {
            out.push_str(&format!(", #{offset}"));
        }
        out.push_str(if writeback { "]!" } else { "]" });
    }
    if rn == 15 {
        out.push_str("\t@ ");
        ctx.vic = 0;
        let lit = (((ctx.pc + 4) & !3) as i64).wrapping_add(offset) as u64;
        let s = sym(ctx.libc, lit);
        out.push_str(&s);
    }
    out
}

/// coproc `%A`/`%K`：vldr/vstr 等寻址（P/W/U 位 24/21/23）。
fn coproc_addr(ctx: &mut Ctx, k: bool) -> String {
    let g = ctx.given;
    let mut out = String::new();
    let rn = ((g >> 16) & 0xf) as usize;
    let mut offset = if k { (g & 0x7f) as i64 } else { (g & 0xff) as i64 };
    let p = g & 0x0100_0000 != 0;
    let w = g & 0x0020_0000 != 0;
    let n = g & 0x0080_0000 == 0;
    out.push('[');
    out.push_str(REG[rn]);
    if p || w {
        // 偏移按 cp 缩放
        offset *= if ctx.cp_num == 9 { 2 } else { 4 };
        if n {
            offset = -offset;
        }
        if rn != 15 {
            ctx.vic = offset;
        }
    }
    if p {
        if offset != 0 {
            out.push_str(&format!(", #{offset}]{}", if w { "!" } else { "" }));
        } else if n {
            out.push_str(", #-0]");
        } else {
            out.push(']');
        }
    } else {
        out.push(']');
        if w {
            if offset != 0 {
                out.push_str(&format!(", #{offset}"));
            } else if n {
                out.push_str(", #-0");
            }
        } else {
            out.push_str(&format!(", {{{offset}}}"));
            ctx.vic = offset;
        }
    }
    if rn == 15 && (p || w) {
        out.push_str("\t@ ");
        // thumb 32 位指令：offset + pc + 4 - (pc & 3)（bytes_per_chunk=2）
        let lit = (offset + ctx.pc as i64 + 4 - (ctx.pc & 3) as i64) as u64;
        let s = sym(ctx.libc, lit);
        out.push_str(&s);
    }
    out
}

fn thumb_expand_imm(bits: u32) -> u32 {
    let imm8 = bits & 0xff;
    match (bits & 0xf00) >> 8 {
        0 => imm8,
        1 => (imm8 << 16) | imm8,
        2 => (imm8 << 24) | (imm8 << 8),
        3 => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
        _ => {
            let modn = (bits & 0xf80) >> 7;
            let i8b = (bits & 0x7f) | 0x80;
            i8b.wrapping_shl(32 - modn) | (i8b >> modn)
        }
    }
}

fn reglist16(g: u32, lr: bool, pc: bool) -> String {
    let mut regs: Vec<&str> = Vec::new();
    for reg in 0..8usize {
        if g & (1 << reg) != 0 {
            regs.push(REG[reg]);
        }
    }
    if lr && g & (1 << 8) != 0 {
        regs.push(REG[14]);
    }
    if pc && g & (1 << 8) != 0 {
        regs.push(REG[15]);
    }
    format!("{{{}}}", regs.join(", "))
}

fn data_barrier_option(opt: u32) -> Option<&'static str> {
    Some(match opt & 0xf {
        0xf => "sy",
        0xe => "st",
        0xd => "ld",
        0xb => "ish",
        0xa => "ishst",
        0x9 => "ishld",
        0x7 => "un",
        0x6 => "unst",
        0x5 => "nshld",
        0x3 => "osh",
        0x2 => "oshst",
        0x1 => "oshld",
        _ => return None,
    })
}

fn psr_name(regno: u32) -> &'static str {
    match regno {
        0x0 => "APSR",
        0x1 => "IAPSR",
        0x2 => "EAPSR",
        0x3 => "PSR",
        0x5 => "IPSR",
        0x6 => "EPSR",
        0x7 => "IEPSR",
        0x8 => "MSP",
        0x9 => "PSP",
        0xa => "MSPLIM",
        0xb => "PSPLIM",
        0x10 => "PRIMASK",
        0x11 => "BASEPRI",
        0x12 => "BASEPRI_MAX",
        0x13 => "FAULTMASK",
        0x14 => "CONTROL",
        _ => "<unknown>",
    }
}

fn extract_flow(ctx: &Ctx, text: &str) -> Option<Flow> {
    if let Some(t) = ctx.branch_target {
        return Some(if is_call_mnemonic(text) { Flow::Call(t) } else { Flow::Branch(t) });
    }
    if ctx.indirect {
        return Some(Flow::Indirect);
    }
    let body = text.splitn(2, '\t').nth(1).unwrap_or("");
    let mn_end = body.find(['\t', ' ']).unwrap_or(body.len());
    let mn = &body[..mn_end];
    if matches!(mn, "bx" | "blx" | "bxns" | "blxns") && !body.contains('<') {
        return Some(Flow::Indirect);
    }
    if matches!(mn, "tbb" | "tbh") {
        return Some(Flow::Indirect);
    }
    if (mn.starts_with("pop") || mn.starts_with("ldm")) && body.contains("pc") {
        return Some(Flow::Indirect);
    }
    None
}

fn is_call_mnemonic(text: &str) -> bool {
    let body = text.splitn(2, '\t').nth(1).unwrap_or("");
    let mn_end = body.find(['\t', ' ']).unwrap_or(body.len());
    body[..mn_end].starts_with("bl")
}

// ---------------------------------------------------------------------------
// A32 兜底（dp imm / b / bl / bx / ldr / str / push / pop）—— GT 无 A32 行
// ---------------------------------------------------------------------------

fn a32_walk(libc: &Libc, lo: u64, hi: u64) -> Vec<Line> {
    let mut out = Vec::new();
    let mut addr = lo;
    while addr < hi {
        if let Some(n) = zero_run_skip(libc, addr, hi) {
            addr += n;
            continue;
        }
        let Some(bytes) = libc.bytes_at_vaddr(addr, 4) else { break };
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        match a32(libc, addr, word) {
            Some((t, flow)) => out.push(mk(addr, t, 4, flow)),
            None => out.push(mk(
                addr,
                format!("\t\t@ <UNDEFINED> instruction: 0x{word:08x}"),
                4,
                None,
            )),
        }
        addr += 4;
    }
    out
}

fn a32(libc: &Libc, addr: u64, word: u32) -> Option<(String, Option<Flow>)> {
    let cond = (word >> 28) as usize;
    let mut branch_target = None;
    let mut is_call = false;
    let mut indirect = false;
    let text = if word & 0x0e00_0000 == 0x0a00_0000 {
        let off = sext(word & 0xff_ffff, 24) << 2;
        let target = (addr as i64 + 8 + off) as u64;
        branch_target = Some(target);
        is_call = word & 0x0100_0000 != 0;
        let name = if is_call { "bl" } else { "b" };
        format!("{name}{}\t{}", COND17[cond], sym(libc, target))
    } else if word & 0x0ff0_fff0 == 0x0120_0010 {
        indirect = true;
        format!("bx{}\t{}", COND17[cond], REG[(word & 0xf) as usize])
    } else if word & 0x0de0_0000 == 0x0400_0000 && word & 0x10 == 0 {
        ldr_str_a32(libc, addr, word, cond)
    } else if word & 0x0de0_0000 == 0x0200_0000 && word & 0x10 == 0 {
        dp_imm_a32(word, cond)
    } else if (word & 0x0fff_0000) == 0xe92d_0000 & 0x0fff_0000 {
        format!("push{}\t{{{}}}", COND17[cond], reglist32(word & 0xffff))
    } else if (word & 0x0fff_0000) == (0xe8bd_0000 & 0x0fff_0000) {
        indirect = word & 0x8000 != 0;
        format!("pop{}\t{{{}}}", COND17[cond], reglist32(word & 0xffff))
    } else {
        return None;
    };
    let flow = if let Some(t) = branch_target {
        Some(if is_call { Flow::Call(t) } else { Flow::Branch(t) })
    } else if indirect {
        Some(Flow::Indirect)
    } else {
        None
    };
    Some((text, flow))
}

fn ldr_str_a32(libc: &Libc, addr: u64, word: u32, cond: usize) -> String {
    let rd = ((word >> 12) & 0xf) as usize;
    let rn = ((word >> 16) & 0xf) as usize;
    let l = word & 0x0010_0000 != 0;
    let name = if l { "ldr" } else { "str" };
    let imm12 = word & 0xfff;
    let u = word & 0x0080_0000 != 0;
    let off: i64 = if u { imm12 as i64 } else { -(imm12 as i64) };
    if rn == 15 && word & 0x0200_0000 == 0 {
        let lit = (addr as i64 + 8 + off) as u64;
        return format!(
            "{name}{}\t{}, [pc, #{off}]\t@ ({})",
            COND17[cond],
            REG[rd],
            sym(libc, lit)
        );
    }
    if word & 0x0200_0000 == 0 {
        let sign = if u { "" } else { "-" };
        let addr_txt = if imm12 == 0 {
            format!("[{}]", REG[rn])
        } else {
            format!("[{}, #{sign}{imm12}]", REG[rn])
        };
        let comment = imm_comment(off);
        format!("{name}{}\t{}, {addr_txt}{comment}", COND17[cond], REG[rd])
    } else {
        let rm = (word & 0xf) as usize;
        format!("{name}{}\t{}, [{}, {}]", COND17[cond], REG[rd], REG[rn], REG[rm])
    }
}

fn dp_imm_a32(word: u32, cond: usize) -> String {
    let op = (word >> 21) & 0xf;
    let rn = ((word >> 16) & 0xf) as usize;
    let rd = ((word >> 12) & 0xf) as usize;
    let imm = arm_expand_imm(word & 0xfff) as i64;
    let name = match (op, word & 0x0010_0000 != 0) {
        (0, false) => "and",
        (0, true) => "ands",
        (1, false) => "eor",
        (1, true) => "eors",
        (2, false) => "sub",
        (2, true) => "subs",
        (3, false) => "rsb",
        (3, true) => "rsbs",
        (4, false) => "add",
        (4, true) => "adds",
        (10, false) => "cmp",
        (11, false) => "cmn",
        (12, false) => "orr",
        (12, true) => "orrs",
        (13, false) => "mov",
        (13, true) => "movs",
        (14, false) => "bic",
        (14, true) => "bics",
        (15, false) => "mvn",
        (15, true) => "mvns",
        _ => return String::new(),
    };
    if matches!(op, 8..=11) {
        return format!("{name}{}\t{}, #{imm}{}", COND17[cond], REG[rn], imm_comment(imm));
    }
    if op == 13 || op == 15 {
        format!("{name}{}\t{}, #{imm}{}", COND17[cond], REG[rd], imm_comment(imm))
    } else {
        format!(
            "{name}{}\t{}, {}, #{imm}{}",
            COND17[cond],
            REG[rd],
            REG[rn],
            imm_comment(imm)
        )
    }
}

fn reglist32(mask: u32) -> String {
    let mut regs = Vec::new();
    for i in 0..16usize {
        if mask & (1 << i) != 0 {
            regs.push(REG[i]);
        }
    }
    regs.join(", ")
}

fn arm_expand_imm(imm12: u32) -> u32 {
    (imm12 & 0xff).rotate_right(((imm12 >> 8) & 0xf) * 2)
}

fn imm_comment(v: i64) -> String {
    if v > 32 || v < -16 {
        format!("\t@ 0x{:x}", v as u64)
    } else {
        String::new()
    }
}

/// printf `%.<prec>g` 的 Rust 等价（NEON 浮点常量注释）。
fn fmt_g(val: f64, prec: usize) -> String {
    if val == 0.0 {
        return "0".to_string();
    }
    let exp = val.abs().log10().floor() as i32;
    if exp < -4 || exp >= prec as i32 {
        // 指数形式：d.ddde±XX
        let s = format!("{:.*e}", prec.saturating_sub(1), val);
        if let Some(epos) = s.find('e') {
            let (mant, ex) = s.split_at(epos);
            let mant = mant.trim_end_matches('0').trim_end_matches('.');
            let ex_num: i32 = ex[1..].parse().unwrap_or(0);
            format!("{mant}e{}{:02}", if ex_num < 0 { '-' } else { '+' }, ex_num.abs())
        } else {
            s
        }
    } else {
        let decimals = (prec as i32 - 1 - exp).max(0) as usize;
        let s = format!("{:.*}", decimals, val);
        let s = s.trim_end_matches('0').trim_end_matches('.');
        s.to_string()
    }
}

fn sext(v: u32, bits: u32) -> i64 {
    if bits == 0 || bits > 32 {
        return v as i64;
    }
    let shift = 32 - bits;
    (((v << shift) as i32) >> shift) as i64
}
