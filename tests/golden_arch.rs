//! 架构管线回归：aarch64（master 2.1.1 语义）等非 x86 架构的真样本 e2e。
//!
//! 样本集来自 ROG_LIBC_SAMPLES_DIR（默认 ~/Documents/Codes/CTF/tools/rog_libc_samples，
//! 即 Phase ② 构建的强制样本集）；环境变量可重定向（无硬编码绝对路径）。
//! 黄金值来自 one_gadget master（f6e57f0）在对应样本上的输出。

use std::path::PathBuf;
use std::process::Command;

fn samples_dir() -> PathBuf {
    std::env::var_os("ROG_LIBC_SAMPLES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../CTF/tools/rog_libc_samples")
                .canonicalize()
                .unwrap_or_else(|_| {
                    PathBuf::from("ROG_LIBC_SAMPLES_DIR")
                })
        })
}

fn run_rog(libc: &std::path::Path, level: u32) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rog"))
        .arg(libc)
        .arg("-f")
        .arg("-l")
        .arg(level.to_string())
        .arg("--raw")
        .output()
        .expect("run rog");
    assert!(out.status.success(), "rog exited with {:?}", out.status);
    String::from_utf8(out.stdout).expect("utf8")
}

/// 黄金偏移表：样本文件名 → master 2.1.1 的 -l 0 / -l 1 偏移集（十进制，--raw）。
/// 值来自 /tmp/og-master 的 `one_gadget <sample> -l N --raw` 实测，
/// 与 rog 全部 10 个样本逐字节一致（pretty 格式亦逐字节一致）。
const GOLDEN_AARCH64_L0: &[(&str, &[u64])] = &[
    ("libc-2.23.so", &[0x3d6d4, 0x3d6d8, 0x3d718]),
    ("libc-2.23-0ubuntu3.so", &[0x3d694, 0x3d698, 0x3d6d8]),
    ("libc-2.24.so", &[0x3c970, 0x9cec8, 0x9cecc]),
    ("libc-2.27.so", &[0x3f160, 0x63e90, 0xa321c, 0xa32e8]),
    ("libc-2.27-3ubuntu1.5.so", &[0x3f220, 0x63f50, 0xa30dc, 0xa31a8]),
    ("libc-2.31-0ubuntu9.18.so", &[0xa4928, 0xa4a6c, 0xbfc68]),
    ("libc-2.35-0ubuntu3.15.so", &[0xbaf04, 0xbaf3c]),
    ("libc-2.39-0ubuntu8.9.so", &[0x4cb30, 0x4cb34, 0xbde90, 0xd8a04]),
    ("libc-2.41-6ubuntu1.2.so", &[0x4a924, 0x4a928, 0xc3d78]),
    ("libc-2.43.so", &[0x4bc00, 0x4bc04, 0x4bc08, 0x4bc0c, 0x4bc10, 0x4bc14, 0x4bc18, 0x4bc1c]),
];

const GOLDEN_AARCH64_L1: &[(&str, &[u64])] = &[
    ("libc-2.23.so", &[0x3d6c4, 0x3d6cc, 0x3d6d0, 0x3d6d4, 0x3d6d8, 0x3d6e8, 0x3d718, 0x60c1c, 0x60c20, 0x9b9e0, 0x9b9e4, 0x9bc5c]),
    ("libc-2.23-0ubuntu3.so", &[0x3d684, 0x3d68c, 0x3d690, 0x3d694, 0x3d698, 0x3d6a8, 0x3d6d8, 0x60b74, 0x60b78, 0x9b9a0, 0x9b9a4, 0x9bc1c]),
    ("libc-2.24.so", &[0x3c91c, 0x3c924, 0x3c928, 0x3c92c, 0x3c930, 0x3c940, 0x3c970, 0x61484, 0x61488, 0x9cec8, 0x9cecc]),
    ("libc-2.27.so", &[0x3f158, 0x3f15c, 0x3f160, 0x3f168, 0x3f16c, 0x3f174, 0x3f184, 0x3f1a8, 0x63e7c, 0x63e88, 0x63e90, 0xa321c, 0xa32e8, 0xa32ec]),
    ("libc-2.27-3ubuntu1.5.so", &[0x3f218, 0x3f21c, 0x3f220, 0x3f228, 0x3f22c, 0x3f234, 0x3f244, 0x3f268, 0x63f3c, 0x63f48, 0x63f50, 0xa30dc, 0xa31a8, 0xa31ac]),
    ("libc-2.31-0ubuntu9.18.so", &[0x40108, 0x40138, 0x4013c, 0x4014c, 0x40150, 0x40154, 0x40158, 0x4015c, 0x65688, 0x6569c, 0x656a0, 0xa4928, 0xa4a38, 0xa4a6c, 0xbfc68]),
    ("libc-2.35-0ubuntu3.15.so", &[0x46ccc, 0x46cfc, 0x46d00, 0x46d10, 0x46d14, 0x46d18, 0x6d7f8, 0x6d80c, 0x6d810, 0xbaf04, 0xbaf3c]),
    ("libc-2.39-0ubuntu8.9.so", &[0x4cadc, 0x4cb10, 0x4cb1c, 0x4cb20, 0x4cb24, 0x4cb28, 0x4cb2c, 0x4cb30, 0x4cb34, 0x714d4, 0x714e0, 0x714e4, 0x714e8, 0x714ec, 0x714f0, 0x714f4, 0x714f8, 0x714fc, 0x71500, 0xbde58, 0xbde90, 0xd8a04]),
    ("libc-2.41-6ubuntu1.2.so", &[0x4a8d0, 0x4a904, 0x4a910, 0x4a914, 0x4a918, 0x4a91c, 0x4a920, 0x4a924, 0x4a928, 0x73124, 0x73130, 0x73134, 0x73138, 0x7313c, 0x73140, 0x73144, 0x73148, 0x7314c, 0xc3d40, 0xc3d78, 0xdf50c, 0xdf5b8, 0xdf5bc]),
    ("libc-2.43.so", &[0x4bbf8, 0x4bbfc, 0x4bc00, 0x4bc04, 0x4bc08, 0x4bc0c, 0x4bc10, 0x4bc14, 0x4bc18, 0x4bc1c, 0x4bc20, 0x4bc24, 0x7667c, 0x76680, 0x76684, 0x76688, 0x7668c, 0x76690, 0x76694, 0x76698, 0x7669c, 0x766a0, 0x766b0, 0xc7ac8, 0xc7b00, 0xe31c4, 0xe3270, 0xe3274]),
];

fn check_golden(level: u32, golden: &[(&str, &[u64])]) {
    let dir = samples_dir().join("glibc/aarch64");
    if !dir.exists() {
        eprintln!("samples dir missing: {} — skipping", dir.display());
        return;
    }
    for (name, want) in golden {
        let p = dir.join(name);
        if !p.exists() {
            eprintln!("{name} not in samples — skipping");
            continue;
        }
        let got = run_rog(&p, level);
        let got_offsets: Vec<u64> =
            got.split_whitespace().map(|s| s.parse().unwrap()).collect();
        assert_eq!(&got_offsets, want, "{name} l{level}: offsets diverge from master");
    }
}

#[test]
fn aarch64_glibc_golden_l0() {
    check_golden(0, GOLDEN_AARCH64_L0);
}

#[test]
fn aarch64_glibc_golden_l1() {
    check_golden(1, GOLDEN_AARCH64_L1);
}

/// 冒烟：每个 aarch64 glibc 样本 l1 都能跑完且产出非空 gadget 集。
#[test]
fn aarch64_glibc_smoke() {
    let dir = samples_dir().join("glibc/aarch64");
    if !dir.exists() {
        eprintln!("samples dir missing: {} — skipping", dir.display());
        return;
    }
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("read aarch64 dir").flatten() {
        let p = entry.path();
        if p.extension().is_none_or(|e| e != "so") {
            continue;
        }
        let out = run_rog(&p, 1);
        assert!(!out.trim().is_empty(), "{} produced no gadgets", p.display());
        checked += 1;
    }
    assert!(checked >= 8, "expected >=8 aarch64 samples, checked {checked}");
}
