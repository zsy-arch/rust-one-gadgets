//! mips o32 textgen：把指令字渲染为 objdump（`--no-show-raw-insn -w -d`）行文本。
//!
//! 编码：`opcode[31:26] | rs[25:21] | rt[20:16] | rd[15:11] | shamt[10:6] | funct[5:0]`。
//! 端序由 `Libc.mips_el` 决定（BE=N / LE=V）。
//!
//! 渲染细节（objdump 语义）：
//! - 寄存器名 o32：zero/at/v0-v1/a0-a3/t0-t7/s0-s8/t8-t9/k0-k1/gp/sp/fp/ra
//! - 分支目标 = 行地址+4+(imm<<2)（符号扩展 16 位）
//! - j/jal 目标 = (行地址+4 & 0xf0000000) | (index<<2)
//! - `li` 是 addiu rt,rs,0 / ori rt,rs,imm 的 objdump 伪指令形式；
//!   `move` 是 or/addu rd,rs,zero；`nop` 是 sll zero,zero,0
//! - bgezal zero,imm 渲染为 `bal <target>`；bltzal 反向
//! - SPECIAL3 bshfl：wsbh/seb/seh 按 shamt
//! - 符号尾注 `<name+off>` 由调用侧（fetcher）附加；这里只产裸行

use crate::elf::Libc;

/// o32 寄存器名（GPR 编号 → 名称；mips_gpr_names_oldabi——reg30 是 s8 非 fp）。
const REGS: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp",
    "s8", "ra",
];

fn reg(n: u32) -> &'static str {
    REGS[(n & 31) as usize]
}

/// 符号扩展 16 位。
fn simm16(word: u32) -> i64 {
    let h = word & 0xffff;
    if h & 0x8000 != 0 {
        h as i64 - 0x10000
    } else {
        h as i64
    }
}

/// 无符号 16 位（andi/ori/xori 的零扩展 imm）。
fn zimm16(word: u32) -> i64 {
    (word & 0xffff) as i64
}

/// HINT 格式立即数（mips-formats.h `i`/`q`/`<` 等）：`0x%x` hex。
fn hx(v: i64) -> String {
    format!("0x{v:x}")
}

/// 分支目标 = addr+4+(simm<<2)。
fn branch_target(addr: u64, word: u32) -> u64 {
    (addr as i64 + 4 + (simm16(word) << 2)) as u64
}

/// j/jal 目标 = ((addr+4) & 0xf0000000) | (index << 2)。
fn jump_target(addr: u64, word: u32) -> u64 {
    ((addr + 4) & 0xf0000000) | (((word & 0x03ff_ffff) as u64) << 2)
}

/// 解码一个指令字为 `mnemonic\toperands` 文本（无地址前缀）。
/// 返回 None 表示无法解码（.word 渲染由调用侧处理）。
#[allow(dead_code)]
pub fn decode(word: u32, addr: u64) -> Option<String> {
    decode_isa(word, addr, true)
}

/// r2：mips32r2+ 指令（rdhwr/seb/seh/ext/ins/wsbh/rotr/movf/movt/mfhc1/mthc1）
/// 在 mips2（r2 之前）渲染为 .word（opcode_is_member 拒绝）。
pub fn decode_isa(word: u32, addr: u64, r2: bool) -> Option<String> {
    let opcode = word >> 26;
    let rs = (word >> 21) & 31;
    let rt = (word >> 16) & 31;
    let rd = (word >> 11) & 31;
    let shamt = (word >> 6) & 31;
    let funct = word & 0x3f;
    let r = |n: u32| reg(n).to_string();
    match opcode {
        0x00 => {
            // SPECIAL
            if word == 0 {
                return Some("nop".into()); // sll zero,zero,0
            }
            match funct {
                0x00 => Some(format!("sll\t{},{},{}", r(rd), r(rt), hx(shamt as i64))),
                0x02 => {
                    if rs == 0 {
                        Some(format!("srl\t{},{},{}", r(rd), r(rt), hx(shamt as i64)))
                    } else if r2 {
                        // ror 别名（mips-opc 0x00200002 先于 srl 命中；rotr 是 r2）
                        Some(format!("ror\t{},{},{}", r(rd), r(rt), hx(shamt as i64)))
                    } else {
                        None
                    }
                }
                0x03 => Some(format!("sra\t{},{},{}", r(rd), r(rt), hx(shamt as i64))),
                0x04 => Some(format!("sllv\t{},{},{}", r(rd), r(rt), r(rs))),
                0x06 => {
                    if shamt == 1 && r2 {
                        Some(format!("rotrv\t{},{},{}", r(rd), r(rt), r(rs)))
                    } else {
                        Some(format!("srlv\t{},{},{}", r(rd), r(rt), r(rs)))
                    }
                }
                0x07 => Some(format!("srav\t{},{},{}", r(rd), r(rt), r(rs))),
                0x08 => Some(format!("jr\t{}", r(rs))),
                0x09 => {
                    if rd == 31 {
                        Some(format!("jalr\t{}", r(rs)))
                    } else {
                        Some(format!("jalr\t{},{}", r(rd), r(rs)))
                    }
                }
                0x0a => Some(format!("movz\t{},{},{}", r(rd), r(rs), r(rt))),
                0x0b => Some(format!("movn\t{},{},{}", r(rd), r(rs), r(rt))),
                0x01 => {
                    // movf/movt rd,rs,$fccN（tf = rt bit0；cc = rt>>2）
                    let tf = rt & 1;
                    let cc = rt >> 2;
                    let mn = if tf == 0 { "movf" } else { "movt" };
                    Some(if cc == 0 {
                        format!("{mn}\t{},{}", r(rd), r(rs))
                    } else {
                        format!("{mn}\t{},{},$fcc{cc}", r(rd), r(rs))
                    })
                }
                0x0c => Some("syscall".into()),
                0x0d => {
                    // break code：[25:16]（mask 0xfc00ffff）；0 → 无操作数。
                    // 打印 hex（WANT `break 0xff`）
                    let code = (word >> 16) & 0x3ff;
                    if code == 0 {
                        Some("break".into())
                    } else {
                        Some(format!("break\t{}", hx(code as i64)))
                    }
                }
                0x0f => Some("sync".into()),
                0x10 => Some(format!("mfhi\t{}", r(rd))),
                0x11 => Some(format!("mthi\t{}", r(rs))),
                0x12 => Some(format!("mflo\t{}", r(rd))),
                0x13 => Some(format!("mtlo\t{}", r(rs))),
                0x18 => Some(format!("mult\t{},{}", r(rs), r(rt))),
                0x19 => Some(format!("multu\t{},{}", r(rs), r(rt))),
                0x1a => {
                    // div "z,s,t"（rd=0 打 3 操作数；I1 路径）
                    Some(format!("div\t{},{},{}", r(rd), r(rs), r(rt)))
                }
                0x1b => Some(format!("divu\t{},{},{}", r(rd), r(rs), r(rt))),
                0x20 => Some(format!("add\t{},{},{}", r(rd), r(rs), r(rt))),
                0x21 => {
            if rt == 0 && shamt == 0 && rd != 0 {
                // move d,s（addu rd,rs,zero；mips-opc 464）
                Some(format!("move\t{},{}", r(rd), r(rs)))
            } else {
                Some(format!("addu\t{},{},{}", r(rd), r(rs), r(rt)))
            }
        }
                0x22 => Some(format!("sub\t{},{},{}", r(rd), r(rs), r(rt))),
                0x23 => {
                    if rs == 0 {
                        // negu d,w（subu rd,zero,rt；mips-opc 1638 先命中）
                        Some(format!("negu\t{},{}", r(rd), r(rt)))
                    } else {
                        Some(format!("subu\t{},{},{}", r(rd), r(rs), r(rt)))
                    }
                }
                0x24 => Some(format!("and\t{},{},{}", r(rd), r(rs), r(rt))),
                0x25 => {
                    if rt == 0 && shamt == 0 && rd != 0 {
                        // move d,s（or rd,rs,zero；rs 可为 zero —— move a1,zero）
                        Some(format!("move\t{},{}", r(rd), r(rs)))
                    } else {
                        Some(format!("or\t{},{},{}", r(rd), r(rs), r(rt)))
                    }
                }
                0x26 => Some(format!("xor\t{},{},{}", r(rd), r(rs), r(rt))),
                0x27 => Some(format!("nor\t{},{},{}", r(rd), r(rs), r(rt))),
                0x2a => Some(format!("slt\t{},{},{}", r(rd), r(rs), r(rt))),
                0x2b => Some(format!("sltu\t{},{},{}", r(rd), r(rs), r(rt))),
                0x34 => {
                    // teq s,t,q：code = [15:6]（HINT hex）；code==0 且 rd/shamt==0 → 2 操作数
                    let code = (word >> 6) & 0x3ff;
                    if rd == 0 && shamt == 0 {
                        Some(format!("teq\t{},{}", r(rs), r(rt)))
                    } else {
                        Some(format!("teq\t{},{},{}", r(rs), r(rt), hx(code as i64)))
                    }
                }
                _ => None,
            }
        }
        0x01 => {
            // REGIMM
            match rt {
                0x00 => Some(format!("bltz\t{},{:x}", r(rs), branch_target(addr, word))),
                0x01 => Some(format!("bgez\t{},{:x}", r(rs), branch_target(addr, word))),
                0x08 => Some(format!("tgei\t{},{}", r(rs), simm16(word))),
                0x09 => Some(format!("tgeiu\t{},{}", r(rs), simm16(word))),
                0x0a => Some(format!("tlti\t{},{}", r(rs), simm16(word))),
                0x0b => Some(format!("tltiu\t{},{}", r(rs), simm16(word))),
                0x0c => Some(format!("teqi\t{},{}", r(rs), simm16(word))),
                0x0d => Some(format!("tnei\t{},{}", r(rs), simm16(word))),
                0x10 => Some(format!("bltzal\t{},{:x}", r(rs), branch_target(addr, word))),
                0x11 => {
                    // bgezal zero → bal 别名（mips-opc 467 先命中，mask 0xffff0000）
                    if rs == 0 {
                        Some(format!("bal\t{:x}", branch_target(addr, word)))
                    } else {
                        Some(format!("bgezal\t{},{:x}", r(rs), branch_target(addr, word)))
                    }
                }
                _ => None,
            }
        }
        0x02 => Some(format!("j\t{:x}", jump_target(addr, word))),
        0x03 => Some(format!("jal\t{:x}", jump_target(addr, word))),
        0x04 => {
            // beq：rt==0 → beqz 别名；rs==rt==0 → b
            if rs == 0 && rt == 0 {
                Some(format!("b\t{:x}", branch_target(addr, word)))
            } else if rt == 0 {
                Some(format!("beqz\t{},{:x}", r(rs), branch_target(addr, word)))
            } else {
                Some(format!("beq\t{},{},{:x}", r(rs), r(rt), branch_target(addr, word)))
            }
        }
        0x05 => {
            if rt == 0 {
                Some(format!("bnez\t{},{:x}", r(rs), branch_target(addr, word)))
            } else {
                Some(format!("bne\t{},{},{:x}", r(rs), r(rt), branch_target(addr, word)))
            }
        }
        0x06 => Some(format!("blez\t{},{:x}", r(rs), branch_target(addr, word))),
        0x07 => Some(format!("bgtz\t{},{:x}", r(rs), branch_target(addr, word))),
        0x08 => Some(format!("addi\t{},{},{}", r(rt), r(rs), simm16(word))),
        0x09 => {
            // addiu rt,rs,imm：rs==zero → li rt,imm（objdump 伪指令）
            if rs == 0 {
                Some(format!("li\t{},{}", r(rt), simm16(word)))
            } else {
                Some(format!("addiu\t{},{},{}", r(rt), r(rs), simm16(word)))
            }
        }
        0x0a => Some(format!("slti\t{},{},{}", r(rt), r(rs), simm16(word))),
        0x0b => Some(format!("sltiu\t{},{},{}", r(rt), r(rs), simm16(word))),
        0x0c => Some(format!("andi\t{},{},{}", r(rt), r(rs), hx(zimm16(word)))),
        0x0d => {
            // ori rt,rs,imm：rs==zero → li rt,imm（i=HINT → hex）
            if rs == 0 {
                Some(format!("li\t{},{}", r(rt), hx(zimm16(word))))
            } else {
                Some(format!("ori\t{},{},{}", r(rt), r(rs), hx(zimm16(word))))
            }
        }
        0x0e => Some(format!("xori\t{},{},{}", r(rt), r(rs), hx(zimm16(word)))),
        0x0f => Some(format!("lui\t{},0x{:x}", r(rt), zimm16(word))),
        0x1c => {
            // SPECIAL2
            match funct {
                0x02 => Some(format!("mul\t{},{},{}", r(rd), r(rs), r(rt))),
                0x00 => Some(format!("madd\t{},{}", r(rs), r(rt))),
                0x01 => Some(format!("maddu\t{},{}", r(rs), r(rt))),
                0x20 => Some(format!("clz\t{},{}", r(rd), r(rs))),
                0x21 => Some(format!("clo\t{},{}", r(rd), r(rs))),
                0x04 => Some(format!("msub\t{},{}", r(rs), r(rt))),
                0x05 => Some(format!("msubu\t{},{}", r(rs), r(rt))),
                _ => None,
            }
        }
        0x1f if r2 => {
            // SPECIAL3（全部 r2 起）
            match funct {
                0x00 => {
                    let size = rd + 1;
                    let lsb = shamt;
                    Some(format!("ext\t{},{},{},{}", r(rt), r(rs), hx(lsb as i64), hx(size as i64)))
                }
                0x04 => {
                    let msb = rd;
                    let lsb = shamt;
                    Some(format!(
                        "ins\t{},{},{},{}",
                        r(rt),
                        r(rs),
                        hx(lsb as i64),
                        hx((msb - lsb + 1) as i64)
                    ))
                }
                0x20 => match shamt {
                    0x02 => Some(format!("wsbh\t{},{}", r(rd), r(rt))),
                    0x10 => Some(format!("seb\t{},{}", r(rd), r(rt))),
                    0x18 => Some(format!("seh\t{},{}", r(rd), r(rt))),
                    _ => None,
                },
                0x3b => {
                    // rdhwr rt,K：K 是 HW 寄存器（mips3264r2 名表：0-3 语义名，其余 $N）
                    let hwr = match rd {
                        0 => "hwr_cpunum".to_string(),
                        1 => "hwr_synci_step".to_string(),
                        2 => "hwr_cc".to_string(),
                        3 => "hwr_ccres".to_string(),
                        n => format!("${n}"),
                    };
                    Some(format!("rdhwr\t{},{}", r(rt), hwr))
                }
                _ => None,
            }
        }
        0x20 => Some(format!("lb\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x21 => Some(format!("lh\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x22 => Some(format!("lwl\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x23 => Some(format!("lw\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x24 => Some(format!("lbu\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x25 => Some(format!("lhu\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x26 => Some(format!("lwr\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x28 => Some(format!("sb\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x29 => Some(format!("sh\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x2a => Some(format!("swl\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x2b => Some(format!("sw\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x2e => Some(format!("swr\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x30 => Some(format!("ll\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x33 => Some(format!("pref\t{},{}({})", hx(((word >> 16) & 31) as i64), simm16(word), r(rs))),
        0x31 => Some(format!("lwc1\t$f{},{}({})", rt, simm16(word), r(rs))),
        0x35 => Some(format!("ldc1\t$f{},{}({})", rt, simm16(word), r(rs))),
        0x39 => Some(format!("swc1\t$f{},{}({})", rt, simm16(word), r(rs))),
        0x3d => Some(format!("sdc1\t$f{},{}({})", rt, simm16(word), r(rs))),
        0x38 => Some(format!("sc\t{},{}({})", r(rt), simm16(word), r(rs))),
        0x11 => decode_cop1(word, addr),
        _ => None,
    }
}

/// COP1（FPU）：bc1t/bc1f + 常见算术。FPU 窗口内罕见——.word 兜底可接受，
/// 但 GT 一致性要求覆盖。fmt=rs 字段：16=s 17=d 20=w 21=l；cc 判定在 rt[2:0]+ft。
fn decode_cop1(word: u32, addr: u64) -> Option<String> {
    let fmt = (word >> 21) & 31;
    let ft = (word >> 16) & 31;
    let fs = (word >> 11) & 31;
    let fd = (word >> 6) & 31;
    let funct = word & 0x3f;
    let f = |n: u32| format!("$f{n}");
    match fmt {
        0x00 => Some(format!("mfc1\t{},$f{}", reg(ft), fs)),  // mfc1 rt,$fs
        0x02 => cop1_ctrl(ft, fs, false),                     // cfc1 rt,ctrl
        0x04 => Some(format!("mtc1\t{},$f{}", reg(ft), fs)),  // mtc1 rt,$fs
        0x06 => cop1_ctrl(ft, fs, true),                      // ctc1 rt,ctrl
        0x03 => Some(format!("mfhc1\t{},$f{}", reg(ft), fs)), // mfhc1 rt,$fs
        0x07 => Some(format!("mthc1\t{},$f{}", reg(ft), fs)), // mthc1 rt,$fs
        _ => decode_cop1_fmt(word, addr, fmt, ft, fs, fd, funct, f),
    }
}

/// cfc1/ctc1（fmt=2/6）：mips_cp1_names_mips3264（31=c1_fcsr、0=c1_fir、25-28 语义名）。
fn cop1_ctrl(rt: u32, fs: u32, to_fpu: bool) -> Option<String> {
    let ctrl = match fs {
        0 => "c1_fir",
        1 => "c1_ufr",
        4 => "c1_unfr",
        25 => "c1_fccr",
        26 => "c1_fexr",
        28 => "c1_fenr",
        31 => "c1_fcsr",
        _ => return None,
    };
    Some(if to_fpu {
        format!("ctc1\t{},{}", reg(rt), ctrl)
    } else {
        format!("cfc1\t{},{}", reg(rt), ctrl)
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_cop1_fmt(
    word: u32,
    addr: u64,
    fmt: u32,
    ft: u32,
    fs: u32,
    fd: u32,
    funct: u32,
    f: impl Fn(u32) -> String,
) -> Option<String> {
    let _ = (ft,);
    match fmt {
        0x08 => {
            // bc1f/bc1t（rt: cc<<2|tf）；cc≠0 → `$fccN,`
            let tf = (word >> 16) & 1;
            let cc = ((word >> 18) & 7) as u64;
            let mn = if tf == 0 { "bc1f" } else { "bc1t" };
            let tgt = branch_target(addr, word);
            Some(if cc == 0 {
                format!("{mn}\t{tgt:x}")
            } else {
                format!("{mn}\t$fcc{cc},{tgt:x}")
            })
        }
        _ => {
            let fmt_ch = match fmt {
                16 => 's',
                17 => 'd',
                20 => 'w',
                21 => 'l',
                _ => return None,
            };
            if fmt == 20 {
                // w 源：cvt.s.w / cvt.d.w / mov.w / trunc.w.w
                match funct {
                    0x20 => return Some(format!("cvt.s.w\t$f{fd},$f{fs}")),
                    0x21 => return Some(format!("cvt.d.w\t$f{fd},$f{fs}")),
                    0x06 => return Some(format!("mov.w\t$f{fd},$f{fs}")),
                    _ => {}
                }
            }
            // 三目算术
            match funct {
                0x00 => Some(format!("add.{}\t{},{},{}", fmt_ch, f(fd), f(fs), f(ft))),
                0x01 => Some(format!("sub.{}\t{},{},{}", fmt_ch, f(fd), f(fs), f(ft))),
                0x02 => Some(format!("mul.{}\t{},{},{}", fmt_ch, f(fd), f(fs), f(ft))),
                0x03 => Some(format!("div.{}\t{},{},{}", fmt_ch, f(fd), f(fs), f(ft))),
                0x06 => Some(format!("mov.{}\t{},{}", fmt_ch, f(fd), f(fs))),
                0x07 => Some(format!("neg.{}\t{},{}", fmt_ch, f(fd), f(fs))),
                0x0d => Some(format!("trunc.w.{}\t{},{}", fmt_ch, f(fd), f(fs))),
                0x20 => Some(format!("cvt.s.{}\t{},{}", fmt_ch, f(fd), f(fs))),
                0x21 => Some(format!("cvt.d.{}\t{},{}", fmt_ch, f(fd), f(fs))),
                0x30..=0x3f => {
                    // c.cond.fmt $fccN,fs,ft（cc = fd 字段[4:2]）
                    let cond = match funct {
                        0x30 => "f",
                        0x31 => "un",
                        0x32 => "eq",
                        0x33 => "ueq",
                        0x34 => "lt",
                        0x35 => "ult",
                        0x36 => "le",
                        0x37 => "ule",
                        0x38 => "sf",
                        0x39 => "ngle",
                        0x3a => "seq",
                        0x3b => "ngl",
                        0x3c => "lt",
                        0x3d => "nge",
                        0x3e => "le",
                        0x3f => "ngt",
                        _ => unreachable!(),
                    };
                    let cc = fd >> 2;
                    Some(if cc == 0 {
                        format!("c.{}.{}\t{},{}", cond, fmt_ch, f(fs), f(ft))
                    } else {
                        format!("c.{}.{}\t$fcc{},{},{}", cond, fmt_ch, cc, f(fs), f(ft))
                    })
                }
                _ => None,
            }
        }
    }
}

#[allow(dead_code)]
fn cvt_op(funct: u32, from: &str, to: char, fd: u32, fs: u32) -> Option<String> {
    match funct {
        0x20 => Some(format!("cvt.{to}.{from}\t$f{fd},$f{fs}")),
        _ => None,
    }
}

/// 指令是否带延迟槽（objdump.c:3375 的 branch_delay_insns 豁免——上一条是
/// 分支/跳转/调用时禁止跳零，保证延迟槽指令照常解码）。
/// mips-dis.c：SPECIAL jr/jalr、REGIMM 全部、j/jal、beq/bne/blez/bgtz、
/// COP1 bc1t/bc1f（fmt∈{0,2} 且 rt[2:0]∈{0..7} 的 tf 位形式）。
fn is_branch_word(word: u32) -> bool {
    let opcode = word >> 26;
    match opcode {
        0x00 => matches!(word & 0x3f, 0x08 | 0x09), // jr, jalr
        0x01 => true,                                // REGIMM
        0x02..=0x07 => true,                         // j/jal/beq/bne/blez/bgtz
        0x11 => {
            // COP1 bc1t/bc1f
            let fmt = (word >> 21) & 31;
            let rt = (word >> 16) & 31;
            matches!(fmt, 0 | 2) && (rt & 0xe) == 8
        }
        _ => false,
    }
}

/// 反汇编 [lo, hi) 地址范围（可执行段内），产出 objdump 风格行
/// （`addr:\tmnem\tops`，不含符号尾注——mips fetcher 后处理负责）。
///
/// objdump -d 语义（objdump.c disassemble_bytes + disassemble_section，5 样本
/// 30 万行地址流验证）：
/// - 逐 AX section、逐符号分段：stop_offset = min(下一 dynsym FUNC 起点, hi)
/// - 零字节省略：连续零 z 字节，`z >= 8`（跳 `z & !3`）或 `z == rem && z < 3`
///   （全跳）——**延迟槽豁免**：上一条指令带延迟槽时不省略
pub fn disassemble_range(libc: &Libc, lo: u64, hi: u64) -> Vec<String> {
    let seg = match libc.executable_segment() {
        Some(s) => s,
        None => return vec![],
    };
    let lo = lo.max(seg.vaddr) & !3;
    let hi = hi.min(seg.vaddr + seg.file_size);
    let be = !libc.mips_el;
    let mut out = Vec::new();
    let mut addr = lo;
    // 上一条指令是否带延迟槽（跨符号边界保持——disassemble_bytes 的
    // branch_delay_insns 在分段循环外重置为 false……实际每 section 重置；
    // 窗口起点按 false 起步）
    let mut delay_exempt = false;
    while addr + 4 <= hi {
        // stop_offset：下一个 > addr 的 FUNC 起点（不超过 hi）
        let stop = match libc.mips_func_starts.partition_point(|&a| a <= addr) {
            i if i < libc.mips_func_starts.len() => libc.mips_func_starts[i].min(hi),
            _ => hi,
        };
        // 连续零字节数（限制在 section 数据内）
        let mut z = 0u64;
        while addr + z < hi {
            match libc.bytes_at_vaddr(addr + z, 1) {
                Some(b) if b[0] == 0 => z += 1,
                _ => break,
            }
        }
        let rem = stop.saturating_sub(addr);
        if !delay_exempt && (z >= 8 || (z == rem && z < 3)) {
            let skip = if z != rem { z & !3 } else { z };
            addr += skip;
            delay_exempt = false;
            continue;
        }
        let word = match read_word(libc, addr, be) {
            Some(w) => w,
            None => break,
        };
        // r2+：EF_MIPS_ARCH 7=mips32r2 8=mips64r2 9/10=r6（r2 指令集超集）
        let r2 = libc.mips_arch_level >= 7;
        match decode_isa(word, addr, r2) {
            Some(text) => out.push(format!("{addr:x}:\t{}", with_sym_tail(libc, text))),
            None => out.push(format!("{addr:x}:\t.word\t0x{word:08x}")),
        }
        delay_exempt = is_branch_word(word);
        addr += 4;
    }
    out
}

/// 按端序读 addr 处的 32 位指令字（vaddr → 文件偏移）。
fn read_word(libc: &Libc, addr: u64, be: bool) -> Option<u32> {
    let b = libc.bytes_at_vaddr(addr, 4)?;
    Some(if be {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

/// 分支/跳转目标的符号尾注：行末 hex 目标词后附加 ` <sym>`
/// （objdump objdump_print_address 语义——GT：`beqz v0,18d54 <__h_errno@@…+0x18d18>`）。
/// 目标词 = 最后一个纯 hex 词；无符号时保持原样。
fn with_sym_tail(libc: &Libc, text: String) -> String {
    let (mnem, rest) = match text.split_once(char::is_whitespace) {
        Some((m, r)) => (m, r),
        None => return text,
    };
    if !matches!(
        mnem,
        "b" | "bal" | "beq" | "bne" | "beqz" | "bnez" | "blez" | "bgtz" | "bltz" | "bgez"
            | "bltzal" | "bgezal" | "j" | "jal" | "bc1t" | "bc1f"
    ) {
        return text;
    }
    // 最后一个纯 hex 词（剥可能的 cc, 前缀——bc1t cc,tgt）
    let mut best: Option<(usize, &str)> = None;
    for (i, tok) in rest.rsplit(',').enumerate() {
        let tok = tok.trim();
        if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_hexdigit()) {
            best = Some((i, tok));
            break;
        }
    }
    let (_, tgt_str) = match best {
        Some(b) => b,
        None => return text,
    };
    let Ok(tgt) = u64::from_str_radix(tgt_str, 16) else {
        return text;
    };
    let name = libc.nearest_symbol(tgt);
    if name.is_empty() {
        text
    } else {
        let pos = text.rfind(tgt_str).unwrap_or(text.len());
        format!("{} <{}>", &text[..pos + tgt_str.len()], name)
    }
}
