//! ABI 元数据（对齐 one_gadget master abi.rb）：寄存器表、窄视图、caller-saved、返回寄存器。
//!
//! 2.1.1 管线（aarch64/arm/riscv64/mips）与 1.10.0 x86 管线共用。

/// 架构名（小写，作为 ABI 表的键）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AbiArch {
    Amd64,
    I386,
    Aarch64,
    Arm,
    Riscv64,
    Mips,
}

impl AbiArch {
    #[allow(dead_code)] // mips/riscv 切片接入后使用
    pub fn name(&self) -> &'static str {
        match self {
            AbiArch::Amd64 => "amd64",
            AbiArch::I386 => "i386",
            AbiArch::Aarch64 => "aarch64",
            AbiArch::Arm => "arm",
            AbiArch::Riscv64 => "riscv64",
            AbiArch::Mips => "mips",
        }
    }
}

fn regs_str(head: &[&str], numbered: &[(&str, i32, i32)]) -> Vec<String> {
    let mut v: Vec<String> = head.iter().map(|s| s.to_string()).collect();
    for (prefix, lo, hi) in numbered {
        for i in *lo..=*hi {
            v.push(format!("{prefix}{i}"));
        }
    }
    v
}

/// 该架构 objdump 打印的寄存器名全集。
pub fn registers(arch: AbiArch) -> Vec<String> {
    match arch {
        AbiArch::Amd64 => {
            // X86_32 + rax..r15 + xmm8..15
            let mut v = registers(AbiArch::I386);
            for r in ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp"] {
                v.push(r.into());
            }
            v.extend(regs_str(&[], &[("r", 8, 15)]));
            v.extend(regs_str(&[], &[("xmm", 8, 15)]));
            v
        }
        AbiArch::I386 => {
            let mut v: Vec<String> =
                ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
            v.extend(regs_str(&[], &[("xmm", 0, 7)]));
            v
        }
        AbiArch::Aarch64 => {
            let mut v: Vec<String> = ["xzr", "wzr", "sp"].iter().map(|s| s.to_string()).collect();
            for i in 0..=30 {
                v.push(format!("x{i}"));
                v.push(format!("w{i}"));
            }
            v
        }
        AbiArch::Arm => {
            let mut v: Vec<String> = ["sl", "fp", "ip", "sp", "lr", "pc"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            v.extend(regs_str(&[], &[("r", 0, 9)]));
            v
        }
        AbiArch::Riscv64 => {
            let mut v: Vec<String> = ["zero", "ra", "sp", "gp", "tp"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            v.extend(regs_str(&[], &[("t", 0, 6)]));
            v.extend(regs_str(&[], &[("s", 0, 11)]));
            v.extend(regs_str(&[], &[("a", 0, 7)]));
            v
        }
        AbiArch::Mips => {
            let mut v: Vec<String> =
                ["zero", "at", "v0", "v1", "gp", "sp", "fp", "ra"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
            v.extend(regs_str(&[], &[("a", 0, 3)]));
            v.extend(regs_str(&[], &[("t", 0, 9)]));
            v.extend(regs_str(&[], &[("s", 0, 7)]));
            v.extend(regs_str(&[], &[("k", 0, 1)]));
            v
        }
    }
}

/// 窄名 → 全寄存器（写低半可见于全名）。
pub fn narrow_views(arch: AbiArch) -> Vec<(String, String)> {
    match arch {
        AbiArch::Amd64 => {
            let mut v: Vec<(String, String)> = ["ax", "bx", "cx", "dx", "di", "si", "bp", "sp"]
                .iter()
                .map(|r| (format!("e{r}"), format!("r{r}")))
                .collect();
            for i in 8..=15 {
                v.push((format!("r{i}d"), format!("r{i}")));
            }
            v
        }
        AbiArch::I386 | AbiArch::Arm | AbiArch::Riscv64 | AbiArch::Mips => vec![],
        AbiArch::Aarch64 => {
            let mut v: Vec<(String, String)> = (0..=30).map(|i| (format!("w{i}"), format!("x{i}"))).collect();
            v.push(("wzr".into(), "xzr".into()));
            v
        }
    }
}

/// 调用者可破坏寄存器（call 后 clobber）。
pub fn caller_saved(arch: AbiArch) -> Vec<String> {
    match arch {
        AbiArch::Amd64 => {
            let mut v: Vec<String> = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            v.extend(regs_str(&[], &[("xmm", 0, 15)]));
            v
        }
        AbiArch::I386 => {
            let mut v: Vec<String> = ["eax", "ecx", "edx"].iter().map(|s| s.to_string()).collect();
            v.extend(regs_str(&[], &[("xmm", 0, 7)]));
            v
        }
        AbiArch::Aarch64 => (0..=7).chain(9..=18).map(|i| format!("x{i}")).collect(),
        AbiArch::Arm => ["r0", "r1", "r2", "r3", "ip", "lr"].iter().map(|s| s.to_string()).collect(),
        AbiArch::Riscv64 => {
            let mut v: Vec<String> = vec!["ra".into()];
            v.extend(regs_str(&[], &[("a", 0, 7)]));
            v.extend(regs_str(&[], &[("t", 0, 6)]));
            v
        }
        AbiArch::Mips => {
            let mut v: Vec<String> = ["at", "v0", "v1", "gp", "ra"].iter().map(|s| s.to_string()).collect();
            v.extend(regs_str(&[], &[("a", 0, 3)]));
            v.extend(regs_str(&[], &[("t", 0, 9)]));
            v
        }
    }
}

/// 整数返回寄存器（clobber 后置 0）。
pub fn return_register(arch: AbiArch) -> Option<&'static str> {
    match arch {
        AbiArch::Amd64 => Some("rax"),
        AbiArch::I386 => Some("eax"),
        AbiArch::Aarch64 => Some("x0"),
        AbiArch::Arm => Some("r0"),
        AbiArch::Riscv64 => Some("a0"),
        // master: RETURN_REGISTER 无 mips（约束渲染不依赖）
        AbiArch::Mips => None,
    }
}

/// 栈/帧指针寄存器名（ABI#stack_register?）。
pub fn is_stack_register(reg: &str) -> bool {
    matches!(reg, "esp" | "ebp" | "rsp" | "rbp" | "sp" | "x29" | "s0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg_lists() {
        assert!(registers(AbiArch::Aarch64).contains(&"x30".to_string()));
        assert!(registers(AbiArch::Aarch64).contains(&"w29".to_string()));
        assert!(registers(AbiArch::Arm).contains(&"r9".to_string()));
        assert!(!registers(AbiArch::Arm).contains(&"r10".to_string())); // r10 是 sl
        assert!(registers(AbiArch::Riscv64).contains(&"s11".to_string()));
        assert!(registers(AbiArch::Mips).contains(&"t9".to_string()));
        assert!(registers(AbiArch::Mips).contains(&"fp".to_string()));
    }

    #[test]
    fn test_narrow() {
        let nv = narrow_views(AbiArch::Aarch64);
        assert!(nv.contains(&("w0".to_string(), "x0".to_string())));
        assert!(nv.contains(&("wzr".to_string(), "xzr".to_string())));
        let nv64 = narrow_views(AbiArch::Amd64);
        assert!(nv64.contains(&("edi".to_string(), "rdi".to_string())));
    }
}
