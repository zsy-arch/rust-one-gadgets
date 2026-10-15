//! riscv64（RV64GC）textgen：objdump 兼容反汇编行（子集解码器）。
//!
//! 目标是**语义 parity**（与 master 输出逐字节一致所需的最小面），不是全量
//! objdump 字节 parity：模拟器支持的指令类（add/addi/auipc/jal/j/li/lui/mv/
//! nop/sub/not + ld 家族 + sd 家族 + and 家族 + 分支/跳转）按 objdump 格式精确
//! 渲染；其余指令只需正确的**宽度**（2/4 字节：`(hw & 3) == 3` 即 32 位）与不
//! 会撞上支持集的助记符（`.insn` 兜底 → 模拟器拒绝，与 master 的拒绝语义一致）。
//!
//! objdump 格式（/tmp/rv64_gt 与 /tmp/rvc_sweep16.txt 全量扫描实证）：
//! - `地址:\t助记符\t操作数`（两个分隔都是 tab）
//! - 操作数逗号后无空格：`addi a5,a5,-1768`、`sd a5,0(a4)`
//! - shift 立即数 hex（`slli a5,a5,0x3`）；逻辑/算术立即数十进制；lui/auipc hex
//! - 分支/jal 目标：`45e38 <sym+off>`（nearest_symbol 注释）
//! - 压缩指令无 c. 前缀（hint 槽除外：rd=0 打印 c.li/c.mv/c.add 等）
//! - hint/保留编码打印 `c.nop imm`、`.insn N, 0x…`（拒绝路径）
//!
//! RVC 位布局经 /tmp/rvc_sweep16.txt（65,536 半字全量 objdump 扫描）逐项验证，
//! 尤其：Q1 misc-alu 组（f3=100）用 [11:10] 选槽、寄存器是 [9:7]+8 压缩名；
//! Q2 f3=100 的 rs2 是 [6:2] 完整 5 位（c.add/mv/jr/jalr 组）。

use crate::elf::Libc;

/// ABI 寄存器名（x8 = s0；x0 = zero）。
fn reg(no: u32) -> &'static str {
    const NAMES: [&str; 32] = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6",
    ];
    NAMES[no as usize]
}

/// 浮点 ABI 寄存器名（f8-f9 = fs0-fs1，f18-f27 = fs2-fs11）。
fn freg(no: u32) -> &'static str {
    const NAMES: [&str; 32] = [
        "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
        "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
        "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
    ];
    NAMES[no as usize]
}

fn sym(libc: &Libc, addr: u64) -> String {
    let name = libc.nearest_symbol(addr);
    if name.is_empty() {
        format!("{addr:x}")
    } else {
        format!("{addr:x} <{name}>")
    }
}

fn sext(v: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    (((v << shift) as i32) >> shift) as i64
}

/// objdump 零字节省略（同 arm zero_run_skip；端点表复用 arm_sym_starts——
/// 它只是「dynsym STT_FUNC 起点」的排序表，架构无关）。
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

/// 反汇编 [lo, hi)：2 字节步进，压缩/32 位按低 2 位判定。
/// objdump 零字节/符号端点省略与 arm 同款规则（arm zero_run_skip）。
pub fn disassemble_range(libc: &Libc, lo: u64, hi: u64) -> Vec<String> {
    let mut out = Vec::new();
    let mut pc = lo;
    while pc + 2 <= hi {
        if let Some(n) = zero_run_skip(libc, pc, hi) {
            pc += n;
            continue;
        }
        let Some(b2) = libc.bytes_at_vaddr(pc, 2) else { break };
        let hw = u16::from_le_bytes([b2[0], b2[1]]) as u32;
        if hw == 0 {
            // 全零半字：objdump 打 unimp（csrr x0, cycle 伪指令）
            out.push(format!("{pc:x}:\tunimp\t"));
            pc += 2;
            continue;
        }
        let wide = hw & 3 == 3;
        if wide && pc + 4 > hi {
            // 窗口尾只剩 Q3 半字：objdump 打 .short（低半字），前进 2
            out.push(format!("{pc:x}:\t.short\t{hw:#06x}"));
            pc += 2;
            continue;
        }
        let word = if wide {
            let Some(b4) = libc.bytes_at_vaddr(pc, 4) else { break };
            u32::from_le_bytes([b4[0], b4[1], b4[2], b4[3]])
        } else {
            hw
        };
        let body = if wide { decode32(libc, pc, word) } else { decode16(libc, pc, hw) };
        // objdump：地址:⇥mnemonic⇥operands（助记符与操作数之间也是 tab）
        let (mnem, rest) = body.split_once(' ').unwrap_or((&body, ""));
        out.push(format!("{pc:x}:\t{mnem}\t{rest}"));
        pc += if wide { 4 } else { 2 };
    }
    out
}

/// 32 位指令解码（opcode 分派）。
fn decode32(libc: &Libc, pc: u64, w: u32) -> String {
    let opcode = w & 0x7f;
    let rd = (w >> 7) & 0x1f;
    let funct3 = (w >> 12) & 7;
    let rs1 = (w >> 15) & 0x1f;
    let rs2 = (w >> 20) & 0x1f;
    let funct7 = w >> 25;
    match opcode {
        0x13 => {
            // OP-IMM
            let imm = sext(w >> 20, 12);
            match funct3 {
                0 => {
                    if rd == 0 {
                        "nop".into()
                    } else if rs1 == 0 {
                        format!("li {},{}", reg(rd), imm)
                    } else if imm == 0 {
                        format!("mv {},{}", reg(rd), reg(rs1))
                    } else {
                        format!("addi {},{},{}", reg(rd), reg(rs1), imm)
                    }
                }
                1 => {
                    // RV64：funct6=w[31:26]（slli=0），shamt 6 位；其余为 Zbs/Zbb 立即数型
                    let funct6 = w >> 26;
                    let sh = (w >> 20) & 0x3f;
                    match funct6 {
                        0 => format!("slli {},{},{sh:#x}", reg(rd), reg(rs1)),
                        0x0a | 0x0b => format!("bseti {},{},{sh:#x}", reg(rd), reg(rs1)),
                        0x12 | 0x13 => format!("bclri {},{},{sh:#x}", reg(rd), reg(rs1)),
                        0x18 if sh == 0 => format!("clz {},{}", reg(rd), reg(rs1)),
                        0x18 if sh == 1 => format!("ctz {},{}", reg(rd), reg(rs1)),
                        0x18 if sh == 2 => format!("cpop {},{}", reg(rd), reg(rs1)),
                        0x18 if sh == 5 => format!("sext.h {},{}", reg(rd), reg(rs1)),
                        _ => format!(".insn 4, {w:#010x}"),
                    }
                }
                2 => format!("slti {},{},{}", reg(rd), reg(rs1), imm),
                3 => {
                    if imm == 1 {
                        format!("seqz {},{}", reg(rd), reg(rs1))
                    } else {
                        format!("sltiu {},{},{}", reg(rd), reg(rs1), imm)
                    }
                }
                4 => {
                    if imm == -1 {
                        format!("not {},{}", reg(rd), reg(rs1))
                    } else {
                        format!("xori {},{},{}", reg(rd), reg(rs1), imm)
                    }
                }
                5 => {
                    // RV64：funct6=w[31:26]（srli=0、srai=0x10），shamt 6 位
                    let funct6 = w >> 26;
                    let sh = (w >> 20) & 0x3f;
                    match funct6 {
                        0 => format!("srli {},{},{sh:#x}", reg(rd), reg(rs1)),
                        0x10 => format!("srai {},{},{sh:#x}", reg(rd), reg(rs1)),
                        0x12 | 0x13 => format!("bexti {},{},{sh:#x}", reg(rd), reg(rs1)),
                        0x1a => format!("rev8 {},{}", reg(rd), reg(rs1)),
                        _ => format!(".insn 4, {w:#010x}"),
                    }
                }
                6 => format!("ori {},{},{}", reg(rd), reg(rs1), imm),
                7 => {
                    if imm == 255 {
                        format!("zext.b {},{}", reg(rd), reg(rs1))
                    } else {
                        format!("andi {},{},{}", reg(rd), reg(rs1), imm)
                    }
                }
                _ => format!(".insn 4, {w:#010x}"),
            }
        }
        0x1b => {
            // OP-IMM-32
            let imm = sext(w >> 20, 12);
            match funct3 {
                0 => {
                    if imm == 0 {
                        format!("sext.w {},{}", reg(rd), reg(rs1))
                    } else {
                        format!("addiw {},{},{}", reg(rd), reg(rs1), imm)
                    }
                }
                1 => {
                    let sh = w >> 20;
                    match sh >> 5 {
                        0 => format!("slliw {},{},{:#x}", reg(rd), reg(rs1), sh & 0x1f),
                        0x04 => format!("slli.uw {},{},{:#x}", reg(rd), reg(rs1), sh & 0x3f),
                        _ => format!(".insn 4, {w:#010x}"),
                    }
                }
                5 => {
                    let sh = w >> 20;
                    if sh >> 5 == 0 {
                        format!("srliw {},{},{:#x}", reg(rd), reg(rs1), sh & 0x1f)
                    } else if sh >> 5 == 0x20 {
                        format!("sraiw {},{},{:#x}", reg(rd), reg(rs1), sh & 0x1f)
                    } else {
                        format!(".insn 4, {w:#010x}")
                    }
                }
                _ => format!(".insn 4, {w:#010x}"),
            }
        }
        0x33 => {
            // OP
            match (funct3, funct7) {
                (0, 0x00) => format!("add {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (0, 0x20) => {
                    if rs1 == 0 {
                        format!("neg {},{}", reg(rd), reg(rs2))
                    } else {
                        format!("sub {},{},{}", reg(rd), reg(rs1), reg(rs2))
                    }
                }
                (1, 0x00) => format!("sll {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (2, 0x00) => format!("slt {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (3, 0x00) => {
                    if rs1 == 0 {
                        format!("snez {},{}", reg(rd), reg(rs2))
                    } else {
                        format!("sltu {},{},{}", reg(rd), reg(rs1), reg(rs2))
                    }
                }
                (4, 0x00) => format!("xor {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (5, 0x00) => format!("srl {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (5, 0x20) => format!("sra {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (6, 0x00) => format!("or {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (7, 0x00) => format!("and {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                // Zicond（GT 实测）：funct7=0x07，f3=5 → czero.eqz、f3=7 → czero.nez
                (5, 0x07) => format!("czero.eqz {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (7, 0x07) => format!("czero.nez {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                // Zbb/Zba/Zbs 寄存器型（GT 实测）
                (4, 0x24) => format!("bext {},{},{}", reg(rd), reg(rs1), reg(rs2)),   // Zbs
                (1, 0x14) => format!("bset {},{},{}", reg(rd), reg(rs1), reg(rs2)),   // Zbs
                (5, 0x24) => format!("bext {},{},{}", reg(rd), reg(rs1), reg(rs2)),   // Zbs(f3=5)
                (4, 0x05) => format!("min {},{},{}", reg(rd), reg(rs1), reg(rs2)),    // Zbb
                (5, 0x05) => format!("minu {},{},{}", reg(rd), reg(rs1), reg(rs2)),   // Zbb
                (6, 0x05) => format!("max {},{},{}", reg(rd), reg(rs1), reg(rs2)),    // Zbb
                (7, 0x05) => format!("maxu {},{},{}", reg(rd), reg(rs1), reg(rs2)),   // Zbb
                (2, 0x20) => format!("sh2add {},{},{}", reg(rd), reg(rs1), reg(rs2)), // Zba(f3=2)
                (4, 0x20) => format!("sh3add {},{},{}", reg(rd), reg(rs1), reg(rs2)), // Zba(f3=4)
                (3, 0x01) => format!("mulhu {},{},{}", reg(rd), reg(rs1), reg(rs2)),  // M
                (0, 0x01) => format!("mul {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (1, 0x01) => format!("mulh {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (4, 0x01) => format!("div {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (5, 0x01) => format!("divu {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (6, 0x01) => format!("rem {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (7, 0x01) => format!("remu {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (2, 0x10) => format!("sh1add {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (4, 0x10) => format!("sh2add {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (6, 0x10) => format!("sh3add {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                _ => format!(".insn 4, {w:#010x}"),
            }
        }
        0x3b => {
            // OP-32
            match (funct3, funct7) {
                (0, 0x00) => format!("addw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (0, 0x20) => {
                    if rs1 == 0 {
                        format!("negw {},{}", reg(rd), reg(rs2))
                    } else {
                        format!("subw {},{},{}", reg(rd), reg(rs1), reg(rs2))
                    }
                }
                (1, 0x00) => format!("sllw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (5, 0x00) => format!("srlw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (5, 0x20) => format!("sraw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (0, 0x01) => format!("mulw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (4, 0x01) => format!("divw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (5, 0x01) => format!("divuw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (6, 0x01) => format!("remw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (7, 0x01) => format!("remuw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                // Zba/Zbb 32 位型（GT 实测）
                (0, 0x04) if rs2 != 0 => format!("add.uw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (4, 0x10) => format!("sh2add.uw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (6, 0x10) => format!("sh3add.uw {},{},{}", reg(rd), reg(rs1), reg(rs2)),
                (4, 0x04) if rs2 == 0 => format!("zext.h {},{}", reg(rd), reg(rs1)),
                (0, 0x04) if rs2 == 0 => format!("zext.w {},{}", reg(rd), reg(rs1)),
                _ => format!(".insn 4, {w:#010x}"),
            }
        }
        0x03 => {
            // LOAD
            let imm = sext(w >> 20, 12);
            let name = match funct3 {
                0 => "lb",
                1 => "lh",
                2 => "lw",
                3 => "ld",
                4 => "lbu",
                5 => "lhu",
                6 => "lwu",
                _ => return format!(".insn 4, {w:#010x}"),
            };
            format!("{name} {},{}({})", reg(rd), imm, reg(rs1))
        }
        0x23 => {
            // STORE
            let imm = sext(((w >> 25) << 5) | ((w >> 7) & 0x1f), 12);
            let name = match funct3 {
                0 => "sb",
                1 => "sh",
                2 => "sw",
                3 => "sd",
                _ => return format!(".insn 4, {w:#010x}"),
            };
            format!("{name} {},{}({})", reg(rs2), imm, reg(rs1))
        }
        0x63 => {
            // BRANCH
            let imm = (sext(
                (((w >> 31) & 1) << 12) | (((w >> 7) & 1) << 11) | (((w >> 25) & 0x3f) << 5)
                    | (((w >> 8) & 0xf) << 1),
                13,
            )) as u64;
            let target = pc.wrapping_add(imm);
            let ann = sym(libc, target);
            let name = match funct3 {
                0 => "beq",
                1 => "bne",
                4 => "blt",
                5 => "bge",
                6 => "bltu",
                7 => "bgeu",
                _ => return format!(".insn 4, {w:#010x}"),
            };
            if rs2 == 0 {
                let zname = match (name, rs1) {
                    ("beq", _) => "beqz",
                    ("bne", _) => "bnez",
                    ("blt", _) => "bltz",
                    ("bge", _) => "bgez",
                    // 反向拼法：bge zero,rs → blez rs；blt zero,rs → bgtz rs
                    ("bltu", 0) => return format!("blezu {},{}", reg(rs2), ann),
                    _ => return format!("{name} {},{},{}", reg(rs1), reg(rs2), ann),
                };
                format!("{zname} {},{}", reg(rs1), ann)
            } else if rs1 == 0 {
                match name {
                    "blt" => format!("bgtz {},{}", reg(rs2), ann),
                    "bge" => format!("blez {},{}", reg(rs2), ann),
                    _ => format!("{name} {},{},{}", reg(rs1), reg(rs2), ann),
                }
            } else {
                format!("{name} {},{},{}", reg(rs1), reg(rs2), ann)
            }
        }
        0x67 => {
            // JALR
            let imm = sext(w >> 20, 12);
            if rd == 0 && funct3 == 0 && imm == 0 {
                if rs1 == 1 {
                    "ret".into()
                } else {
                    format!("jr {}", reg(rs1))
                }
            } else if funct3 == 0 && imm == 0 && rd == 1 {
                format!("jalr {}", reg(rs1))
            } else if rd == 1 {
                // objdump 折叠：jalr offset(rs1)（目标可解析时附 # 注释）
                let target = ((pc as i64 + imm) & !1) as u64;
                let t = if libc.nearest_symbol(target).is_empty() {
                    format!("jalr {imm}({})", reg(rs1))
                } else {
                    format!("jalr {imm}({}) # {}", reg(rs1), sym(libc, target as u64))
                };
                t
            } else {
                format!("jalr {},{},{}", reg(rd), imm, reg(rs1))
            }
        }
        0x6f => {
            // JAL
            let imm = sext(
                (((w >> 31) & 1) << 20)
                    | (((w >> 12) & 0xff) << 12)
                    | (((w >> 20) & 1) << 11)
                    | (((w >> 21) & 0x3ff) << 1),
                21,
            ) as u64;
            let target = pc.wrapping_add(imm);
            let ann = sym(libc, target);
            if rd == 0 {
                format!("j {ann}")
            } else if rd == 1 {
                format!("jal {ann}")
            } else {
                format!("jal {},{}", reg(rd), ann)
            }
        }
        0x37 => format!("lui {},{:#x}", reg(rd), w >> 12),
        0x17 => format!("auipc {},{:#x}", reg(rd), w >> 12),
        0x0f => "fence rw,rw".to_string(),
        0x73 => {
            // SYSTEM：f3=0 整数指令；f3≥1 是 CSR 伪指令（objdump 按源操作数折叠命名）
            let csr = w >> 20;
            if funct3 == 0 {
                match (csr, rd) {
                    (0, 0) => "ecall".into(),
                    (1, 0) => "ebreak".into(),
                    _ => format!(".insn 4, {w:#010x}"),
                }
            } else {
                let csr_name = |c: u32| match c {
                    0xc00 => "cycle",
                    0xc01 => "time",
                    0xc02 => "instret",
                    0xc20 => "vl",
                    0x003 => "fscsr", // frm+fcsr 聚合（rs1=源寄存器时 frcsr/fscsr）
                    _ => "",
                };
                if csr == 0x003 && funct3 == 2 && rs1 == 0 {
                    // csrrs x0/src=0, 0x3 → frcsr rd
                    let n = if rd == 0 { "frflags" } else { "frcsr" };
                    format!("{n} {}", reg(rd))
                } else if csr == 0x003 && funct3 == 1 && rd == 0 {
                    // csrrw rd=0, src → fscsr rs1
                    format!("fscsr {}", reg(rs1))
                } else {
                    let nm = csr_name(csr);
                    if nm.is_empty() {
                        format!(".insn 4, {w:#010x}")
                    } else {
                        match funct3 {
                            // csrrs rd, csr, rs1=0 → csrr rd, name
                            2 if rs1 == 0 => format!("csrr {},{}", reg(rd), nm),
                            3 if rs1 == 0 => format!("csrr {},{}", reg(rd), nm),
                            _ => format!(".insn 4, {w:#010x}"),
                        }
                    }
                }
            }
        }
        0x57 if funct3 == 7 && w >> 26 == 0x03 => {
            // vsetvli（GT 实测）：vd, avl, e<sew>,<lmul>,ta,ma
            let zimm = w >> 20;
            let sew = ["e8", "e16", "e32", "e64", "?", "?", "?", "?"][((zimm >> 3) & 7) as usize];
            let lmul = ["m1", "m2", "m4", "m8", "?", "mf8", "mf4", "mf2"][zimm as usize & 7];
            let ta = if zimm & 0x40 != 0 { ",ta" } else { "" };
            let ma = if zimm & 0x80 != 0 { ",ma" } else { "" };
            format!("vsetvli {},{},{sew},{lmul}{ta}{ma}", reg(rd), reg(rs1))
        }
        0x57 if funct3 == 7 && w >> 26 == 0x33 => {
            // vsetivli（GT 实测）：vd, uimm5, e<sew>,<lmul>,ta,ma
            let zimm = w >> 20;
            let sew = ["e8", "e16", "e32", "e64", "?", "?", "?", "?"][((zimm >> 3) & 7) as usize];
            let lmul = ["m1", "m2", "m4", "m8", "?", "mf8", "mf4", "mf2"][zimm as usize & 7];
            let ta = if zimm & 0x40 != 0 { ",ta" } else { "" };
            let ma = if zimm & 0x80 != 0 { ",ma" } else { "" };
            format!("vsetivli {},{},{sew},{lmul}{ta}{ma}", reg(rd), rs1)
        }
        0x07 => {
            // LOAD-FP（fld 等；拒绝路径，宽度正确即可）
            let imm = sext(w >> 20, 12);
            if w >> 27 == 0 && (w >> 25) & 1 == 1 {
                // 向量 unit-stride 载入：rs2=0 单位步长；rs2=0x10 → fault-only-first
                let wname = match funct3 {
                    0 => "vle8.v", 5 => "vle16.v", 6 => "vle32.v", 7 => "vle64.v",
                    _ => "",
                };
                if !wname.is_empty() {
                    let ff = if rs2 == 0x10 { "ff" } else { "" };
                    // e8 宽度名后插 ff：vle8ff.v
                    let full = if ff.is_empty() { wname.to_string() } else {
                        wname.replace(".v", "ff.v")
                    };
                    if rs2 == 0 || rs2 == 0x10 {
                        return format!("{full} v{},({})", rd, reg(rs1));
                    }
                }
            }
            if (w >> 25) == 0x03 {
                // vluxei64.v：indexed 载入（GT 实测：f7=0x03）
                if funct3 == 7 {
                    return format!("vluxei64.v v{},({}),v{}", rd, reg(rs1), rs2);
                }
            }
            match funct3 {
                3 => format!("fld {},{}({})", freg(rd), imm, reg(rs1)),
                2 => format!("flw {},{}({})", freg(rd), imm, reg(rs1)),
                _ => format!(".insn 4, {w:#010x}"),
            }
        }
        0x57 => {
            // OPIVV/OPMVV 向量（GT 实测）。vm=bit25 恒 1；vi 型立即数在 rs2[4:0]。
            let f6 = w >> 26;
            let vs = |v: u32| format!("v{v}");
            match (f6, funct3) {
                (0x00, 3) => format!("vadd.vi {},{},{}", vs(rd), vs(rs2), rs1),
                (0x09, 0) => format!("vand.vv {},{},{}", vs(rd), vs(rs2), vs(rs1)),
                (0x0a, 0) => format!("vor.vv {},{},{}", vs(rd), vs(rs2), vs(rs1)),
                _ => match (f6, rs2, funct3) {
                    // RVV 布局（GT 实测）：vs2=[24:20]（rs2 字段）、vs1=[19:15]（rs1 字段）；
                    // OPIVI 立即数 = rs1 字段 5 位；标量 vx 源 = rs1 字段。
                    (0x10, _, 2) if rs1 == 0x11 => format!("vfirst.m {},{}", reg(rd), vs(rs2)),
                    (0x14, 0, 2) if rs1 == 0x11 => format!("vid.v {}", vs(rd)),
                    (0x17, 0, 3) => format!("vmv.v.i {},{}", vs(rd), rs1),
                    (0x17, 0, 4) => format!("vmv.v.x {},{}", vs(rd), reg(rs1)),
                    (0x12, 1, 2) => format!("vzext.vf8 {},{}", vs(rd), vs(rs2)),
                    (0x18, _, 3) => format!("vmseq.vi {},{},{}", vs(rd), vs(rs2), rs1),
                    (0x19, 1, 0) => format!("vmsne.vv {},{},{}", vs(rd), vs(rs2), vs(rs1)),
                    (0x1a, 1, 2) => format!("vmor.mm {},{},{}", vs(rd), vs(rs2), vs(rs1)),
                    (0x25, 1, 6) => format!("vmul.vx {},{},{}", vs(rd), vs(rs2), reg(rs1)),
                    (0x25, 1, 3) => format!("vsll.vi {},{},{}", vs(rd), vs(rs2), rs1),
                    (0x25, 1, 4) => format!("vsll.vx {},{},{}", vs(rd), vs(rs2), reg(rs1)),
                    (0x28, 1 | 2, 4) => format!("vsrl.vx {},{},{}", vs(rd), vs(rs2), reg(rs1)),
                    _ => format!(".insn 4, {w:#010x}"),
                },
            }
        }
        0x27 => {
            // STORE-FP / 向量 unit-stride 存储（GT 实测：rs2=0、vm=1）
            if w >> 27 == 0 && (w >> 25) & 1 == 1 && rs2 == 0 {
                let name = match funct3 {
                    0 => "vse8.v",
                    5 => "vse16.v",
                    6 => "vse32.v",
                    7 => "vse64.v",
                    _ => "",
                };
                if !name.is_empty() {
                    return format!("{name} v{},({})", (w >> 7) & 0x1f, reg(rs1));
                }
            }
            let imm = sext(((w >> 25) << 5) | ((w >> 7) & 0x1f), 12);
            match funct3 {
                3 => format!("fsd {},{}({})", freg(rs2), imm, reg(rs1)),
                2 => format!("fsw {},{}({})", freg(rs2), imm, reg(rs1)),
                _ => format!(".insn 4, {w:#010x}"),
            }
        }
        0x2f => {
            // AMO（拒绝路径）。布局（GT 实测）：funct5 = w[31:27]（0x2=lr、0x3=sc、
            // 0x1=amoswap…），aq = bit26，rl = bit25；宽度由 funct3 bit1 选 w/d。
            let funct5 = w >> 27;
            let wids = if funct3 & 1 != 0 { ".d" } else { ".w" };
            let aq = if w & 0x400_0000 != 0 { ".aq" } else { "" };
            let rl = if w & 0x200_0000 != 0 { ".rl" } else { "" };
            match funct5 {
                0x2 if rs2 == 0 => format!("lr{wids}{aq}{rl} {},({})", reg(rd), reg(rs1)),
                0x3 => format!("sc{wids}{aq}{rl} {},{},({})", reg(rd), reg(rs2), reg(rs1)),
                _ => {
                    let base = match funct5 {
                        0x01 => "amoswap",
                        0x00 => "amoadd",
                        0x04 => "amoxor",
                        0x0c => "amoand",
                        0x08 => "amoor",
                        0x10 => "amomin",
                        0x14 => "amomax",
                        0x18 => "amominu",
                        0x1c => "amomaxu",
                        _ => return format!(".insn 4, {w:#010x}"),
                    };
                    format!("{base}{wids}{aq}{rl} {},{},({})", reg(rd), reg(rs2), reg(rs1))
                }
            }
        }
        _ => format!(".insn 4, {w:#010x}"),
    }
}

/// 压缩指令解码（RVC；objdump 无 c. 前缀，伪指令折叠同基础指令）。
/// 位布局经 /tmp/rvc_sweep16.txt 全量扫描验证。
fn decode16(libc: &Libc, pc: u64, hw: u32) -> String {
    let quadrant = hw & 3;
    let funct3 = hw >> 13;
    let rd = (hw >> 7) & 0x1f; // Q1/Q2 目的寄存器（完整 5 位）
    let rs2f = (hw >> 2) & 0x1f; // Q2 完整 5 位源寄存器
    let b12 = (hw >> 12) & 1;
    let b1110 = (hw >> 10) & 3; // Q1 misc-alu 槽选择
    let rs1p = 8 + ((hw >> 7) & 7); // Q0/Q1 压缩寄存器（+8）
    let rs2p = 8 + ((hw >> 2) & 7);
    match (quadrant, funct3) {
        // ---- Q0 ----
        (0, 0) => {
            // c.addi4spn：nzimm[5:4]=i[12:11], nzimm[9:6]=i[10:7], nzimm[3]=i[5], nzimm[2]=i[6]
            let imm = (((hw >> 11) & 3) << 4)
                | (((hw >> 7) & 0xf) << 6)
                | (((hw >> 5) & 1) << 3)
                | (((hw >> 6) & 1) << 2);
            if imm == 0 {
                return format!(".insn 2, {hw:#06x}");
            }
            format!("addi {},sp,{}", reg(rs2p), imm as i64)
        }
        (0, 2) => {
            // c.lw（GT 实测：uimm[5:3]←i[12:10], uimm2←i6, uimm6←i5）
            let imm = (((hw >> 10) & 7) << 3) | (((hw >> 6) & 1) << 2) | (((hw >> 5) & 1) << 6);
            format!("lw {},{}({})", reg(rs2p), imm as i64, reg(rs1p))
        }
        (0, 4) => {
            // Zcb（GT 实测）：[12:10] 000=c.lbu（uimm=i6+2·i5）、001=c.lhu/c.lh
            // （i6=0 无符号 / 1 有符号，uimm=2·i5）、010=c.sb（uimm=i6+2·i5）
            match (hw >> 10) & 7 {
                0 => {
                    let imm = (((hw >> 5) & 1) << 1) | ((hw >> 6) & 1);
                    format!("lbu {},{}({})", reg(rs2p), imm as i64, reg(rs1p))
                }
                1 => {
                    // imm = i5*2；i6 选 lhu/lh（GT 实测：84dc → lh a5,0(s1)）
                    let imm = (((hw >> 5) & 1) << 1) as i64;
                    if hw & 0x40 != 0 {
                        format!("lh {},{}({})", reg(rs2p), imm, reg(rs1p))
                    } else {
                        format!("lhu {},{}({})", reg(rs2p), imm, reg(rs1p))
                    }
                }
                2 => {
                    let imm = (((hw >> 5) & 1) << 1) | ((hw >> 6) & 1);
                    format!("sb {},{}({})", reg(rs2p), imm as i64, reg(rs1p))
                }
                _ => format!(".insn 2, {hw:#06x}"),
            }
        }
        (0, 3) => {
            // c.ld（GT 实测：uimm[5:3]←i[12:10], uimm[7:6]←i[6:5]）
            let imm = (((hw >> 10) & 7) << 3) | (((hw >> 5) & 3) << 6);
            format!("ld {},{}({})", reg(rs2p), imm as i64, reg(rs1p))
        }
        (0, 6) => {
            // c.sw（同 c.lw 位序）
            let imm = (((hw >> 10) & 7) << 3) | (((hw >> 6) & 1) << 2) | (((hw >> 5) & 1) << 6);
            format!("sw {},{}({})", reg(rs2p), imm as i64, reg(rs1p))
        }
        (0, 7) => {
            // c.sd（同 c.ld 位序）
            let imm = (((hw >> 10) & 7) << 3) | (((hw >> 5) & 3) << 6);
            format!("sd {},{}({})", reg(rs2p), imm as i64, reg(rs1p))
        }
        // ---- Q1 ----
        (1, 0) => {
            // c.addi（rd=0 为 hint：imm=0 → nop，否则保留）
            let imm = sext(((hw >> 2) & 0x1f) | (b12 << 5), 6);
            if rd == 0 {
                if imm == 0 {
                    "nop".into()
                } else {
                    format!(".insn 2, {hw:#06x}")
                }
            } else {
                format!("addi {},{},{}", reg(rd), reg(rd), imm)
            }
        }
        (1, 1) => {
            // c.addiw（rd=0 保留；imm=0 → sext.w）
            let imm = sext(((hw >> 2) & 0x1f) | (b12 << 5), 6);
            if rd == 0 {
                format!(".insn 2, {hw:#06x}")
            } else if imm == 0 {
                format!("sext.w {},{}", reg(rd), reg(rd))
            } else {
                format!("addiw {},{},{}", reg(rd), reg(rd), imm)
            }
        }
        (1, 2) => {
            // c.li（rd=0 hint 保留）
            let imm = sext(((hw >> 2) & 0x1f) | (b12 << 5), 6);
            if rd == 0 {
                format!(".insn 2, {hw:#06x}")
            } else {
                format!("li {},{}", reg(rd), imm)
            }
        }
        (1, 3) => {
            if rd == 2 {
                // c.addi16sp（位映射实测：imm4←i6, imm5←i2, imm6←i5, imm7←i3,
                // imm8←i4, imm9←i12）
                let imm = sext(
                    (((hw >> 12) & 1) << 9)
                        | (((hw >> 4) & 1) << 8)
                        | (((hw >> 3) & 1) << 7)
                        | (((hw >> 5) & 1) << 6)
                        | (((hw >> 2) & 1) << 5)
                        | (((hw >> 6) & 1) << 4),
                    10,
                );
                if imm == 0 {
                    format!(".insn 2, {hw:#06x}")
                } else {
                    format!("addi sp,sp,{imm}")
                }
            } else {
                // c.lui（rd=0/2 与 imm=0 保留）
                let imm = sext((((hw >> 2) & 0x1f) << 12) | (b12 << 17), 18);
                if rd == 0 || imm == 0 {
                    format!(".insn 2, {hw:#06x}")
                } else {
                    format!("lui {},{:#x}", reg(rd), (imm as u32 >> 12) & 0xfffff)
                }
            }
        }
        (1, 4) => {
            // misc-alu：[11:10] 选槽，寄存器 [9:7]+8
            match b1110 {
                0 | 1 => {
                    // c.srli / c.srai（shamt64 → c.xxx64 hint）
                    let sh = (b12 << 5) | ((hw >> 2) & 0x1f);
                    let name = if b1110 == 0 { "srli" } else { "srai" };
                    if sh == 0 {
                        format!("c.{name}64 {}", reg(rs1p))
                    } else {
                        format!("{name} {},{},{sh:#x}", reg(rs1p), reg(rs1p))
                    }
                }
                2 => {
                    // c.andi
                    let imm = sext(((hw >> 2) & 0x1f) | (b12 << 5), 6);
                    format!("andi {},{},{}", reg(rs1p), reg(rs1p), imm)
                }
                _ => {
                    // 寄存器组：b12=0 → sub/xor/or/and；b12=1 且 [6:5]=00/01 → subw/addw
                    let sel = (hw >> 5) & 3;
                    if b12 == 0 {
                        let name = ["sub", "xor", "or", "and"][sel as usize];
                        format!("{name} {},{},{}", reg(rs1p), reg(rs1p), reg(rs2p))
                    } else if sel == 0 {
                        format!("subw {},{},{}", reg(rs1p), reg(rs1p), reg(rs2p))
                    } else if sel == 1 {
                        format!("addw {},{},{}", reg(rs1p), reg(rs1p), reg(rs2p))
                    } else if sel == 2 {
                        // Zcb（GT 实测）：c.mul rs1',rs2'
                        format!("mul {},{},{}", reg(rs1p), reg(rs1p), reg(rs2p))
                    } else if sel == 3 {
                        // Zcb（GT 实测）：单目组，[4:2] 选
                        let name = match (hw >> 2) & 7 {
                            0 => "zext.b",
                            1 => "sext.b",
                            2 => "zext.h",
                            3 => "sext.h",
                            4 => "zext.w",
                            _ => {
                                return format!(".insn 2, {hw:#06x}");
                            }
                        };
                        format!("{name} {},{}", reg(rs1p), reg(rs1p))
                    } else {
                        unreachable!()
                    }
                }
            }
        }
        (1, 5) => {
            // c.j
            let imm = cj_imm(hw);
            let target = pc.wrapping_add(imm as u64);
            format!("j {}", sym(libc, target))
        }
        (1, 6) | (1, 7) => {
            // c.beqz / c.bnez
            let imm = cb_imm(hw);
            let target = pc.wrapping_add(imm as u64);
            let name = if funct3 == 6 { "beqz" } else { "bnez" };
            format!("{name} {},{}", reg(rs1p), sym(libc, target))
        }
        // ---- Q2 ----
        (2, 0) => {
            // c.slli（rd=0 hint；shamt=0 → c.slli64）
            let sh = (b12 << 5) | rs2f;
            if sh == 0 {
                format!("c.slli64 {}", reg(rd))
            } else if rd == 0 {
                format!("c.slli {},{sh:#x}", reg(rd))
            } else {
                format!("slli {},{},{sh:#x}", reg(rd), reg(rd))
            }
        }
        (2, 2) => {
            // c.lwsp（位序 GT 实测：uimm[4:2]←i[6:4], uimm[6:5]←i[3:2], uimm[5]←i12）
            let imm = (b12 << 5) | (((hw >> 4) & 7) << 2) | (((hw >> 2) & 3) << 6);
            if rd == 0 {
                format!(".insn 2, {hw:#06x}")
            } else {
                format!("lw {},{}(sp)", reg(rd), imm as i64)
            }
        }
        (2, 3) => {
            // c.ldsp（位序 GT 实测：imm3←i5, imm4←i6, imm5←i12, imm6←i2,
            // imm7←i3, imm8←i4 —— 位散布非连续域）
            let imm = (b12 << 5)
                | (((hw >> 5) & 1) << 3)
                | (((hw >> 6) & 1) << 4)
                | (((hw >> 2) & 1) << 6)
                | (((hw >> 3) & 1) << 7)
                | (((hw >> 4) & 1) << 8);
            if rd == 0 {
                format!(".insn 2, {hw:#06x}")
            } else {
                format!("ld {},{}(sp)", reg(rd), imm as i64)
            }
        }
        (2, 4) => {
            // c.jr / c.mv / c.ebreak / c.jalr / c.add（rs2 是 [6:2] 完整 5 位）
            if b12 == 0 {
                if rs2f == 0 {
                    if rd == 0 {
                        format!(".insn 2, {hw:#06x}")
                    } else if rd == 1 {
                        "ret".into()
                    } else {
                        format!("jr {}", reg(rd))
                    }
                } else if rd == 0 {
                    // c.mv hint（保留编码 → 拒绝路径）
                    format!(".insn 2, {hw:#06x}")
                } else {
                    format!("mv {},{}", reg(rd), reg(rs2f))
                }
            } else if rs2f == 0 {
                if rd == 0 {
                    "ebreak".into()
                } else {
                    format!("jalr {}", reg(rd))
                }
            } else if rd == 0 {
                // c.add hint（保留编码 → 拒绝路径）
                format!(".insn 2, {hw:#06x}")
            } else {
                format!("add {},{},{}", reg(rd), reg(rd), reg(rs2f))
            }
        }
        (2, 5) => {
            // c.fsdsp（同 c.sdsp 位序）
            let imm = (((hw >> 10) & 7) << 3) | (((hw >> 7) & 7) << 6) | (b12 << 5);
            format!("fsd f{},{}(sp)", rd, imm as i64)
        }
        (2, 6) => {
            // c.swsp（GT 实测：uimm[3:2]←i[10:9], uimm[5:4]←i[12:11], uimm[7:6]←i[8:7]）
            let imm = (((hw >> 9) & 3) << 2) | (((hw >> 11) & 3) << 4) | (((hw >> 7) & 3) << 6);
            format!("sw {},{}(sp)", reg(rs2f), imm as i64)
        }
        (2, 7) => {
            // c.sdsp（GT 实测：imm3←i10, imm4←i11, imm5←i12, imm6←i7, imm7←i8,
            // imm8←i9 —— 位散布）
            let imm = (((hw >> 10) & 7) << 3) | (((hw >> 7) & 7) << 6) | (b12 << 5);
            format!("sd {},{}(sp)", reg(rs2f), imm as i64)
        }
        _ => {
            // Q3 保留槽：objdump 输出 .short（两半字各自独立处理）
            format!(".short {hw:#06x}")
        }
    }
}

/// c.j 立即数（位映射经 GT 实测逐位解出）：
/// off[3:1]←i[5:3]（连续域）、off4←i11、off[9:8]←i[10:9]、off10←i8、
/// off6←i7、off7←i6（交叉）、off5←i2、off11←i12。
fn cj_imm(hw: u32) -> i64 {
    sext(
        (((hw >> 12) & 1) << 11)
            | (((hw >> 11) & 1) << 4)
            | (((hw >> 10) & 1) << 9)
            | (((hw >> 9) & 1) << 8)
            | (((hw >> 8) & 1) << 10)
            | (((hw >> 7) & 1) << 6)
            | (((hw >> 6) & 1) << 7)
            | (((hw >> 3) & 7) << 1)
            | (((hw >> 2) & 1) << 5),
        12,
    )
}

/// c.beqz / c.bnez 立即数（位映射 GT 实测：off1←i3、off2←i4、off3←i10、
/// off4←i11、off5←i2、off6←i5、off7←i6、off8←i12）。
fn cb_imm(hw: u32) -> i64 {
    sext(
        (((hw >> 12) & 1) << 8)
            | (((hw >> 11) & 1) << 4)
            | (((hw >> 10) & 1) << 3)
            | (((hw >> 6) & 1) << 7)
            | (((hw >> 5) & 1) << 6)
            | (((hw >> 4) & 1) << 2)
            | (((hw >> 3) & 1) << 1)
            | (((hw >> 2) & 1) << 5),
        9,
    )
}
