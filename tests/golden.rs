//! 黄金集回归：rog 输出必须与 one_gadget v1.10.0（Ruby 版）逐字节一致。
//!
//! testdata/ 下是 36 个 Ubuntu glibc libc.so.6（amd64 + i386，2.23–2.43），
//! testdata/golden/ 下是对应 `one_gadget -l <0|1|2>` 的参考输出。
//! 覆盖：候选发现（grep -B30 / jmp_case）、符号执行、约束渲染、
//! trim/去重、level 过滤、pretty 格式化全链路。

use std::process::Command;

/// testdata 目录（crate 根）。
fn testdata() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

/// 跑一次 rog，返回 stdout。
fn run_rog(libc: &std::path::Path, level: u32) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rog"))
        .arg(libc)
        .arg("-f") // golden = 全量扫描语义（DB 命中时 one_gadget 也输出预构建结果）
        .arg("-l")
        .arg(level.to_string())
        .output()
        .expect("run rog");
    assert!(out.status.success(), "rog exited with {:?}", out.status);
    String::from_utf8(out.stdout).expect("utf8")
}

/// 36 个 libc 的文件名（testdata/*.so）。
fn all_libcs() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(testdata())
        .expect("read testdata")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "so"))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

#[test]
fn golden_all_libcs_all_levels() {
    let libcs = all_libcs();
    assert!(libcs.len() >= 36, "expected >=36 test libcs, got {}", libcs.len());

    // debug 构建下单 libc ~0.5s：并行 8 线程压到 ~2s
    let chunks: Vec<_> = {
        let mut c = vec![Vec::new(); 8];
        for (i, l) in libcs.iter().enumerate() {
            c[i % 8].push(l.clone());
        }
        c
    };
    let handles: Vec<_> = chunks
        .into_iter()
        .filter(|c| !c.is_empty())
        .map(|chunk| {
            std::thread::spawn(move || {
                let mut failures: Vec<String> = Vec::new();
                for name in chunk {
                    // libc-2.23-0ubuntu3_amd64.so → 2.23-0ubuntu3_amd64
                    let ver = name.trim_start_matches("libc-").trim_end_matches(".so");
                    for level in [0u32, 1, 2] {
                        let golden_path = testdata()
                            .join("golden")
                            .join(format!("{ver}_l{level}.txt"));
                        let Ok(want) = std::fs::read_to_string(&golden_path) else {
                            failures.push(format!("{ver}: missing golden {level}"));
                            continue;
                        };
                        let got = run_rog(&testdata().join(&name), level);
                        if got != want {
                            // 首个差异行，方便定位
                            let mut diff = String::new();
                            for (a, b) in got.lines().zip(want.lines()) {
                                if a != b {
                                    diff = format!("rog: {a:?} | golden: {b:?}");
                                    break;
                                }
                            }
                            failures.push(format!("{ver} L{level}: {diff}"));
                        }
                    }
                }
                failures
            })
        })
        .collect();
    let mut all = Vec::new();
    for h in handles {
        all.extend(h.join().expect("thread"));
    }
    assert!(all.is_empty(), "golden mismatches:\n{}", all.join("\n"));
}

/// 空输出等级也稳定：-l 2 与 -l 1 在无 gadget 的库里一致为空/非空。
#[test]
fn golden_raw_mode_matches_offsets() {
    // pretty 首列偏移应与 --raw 输出一致（对 2.35 抽查）
    let libc = testdata().join("libc-2.35-0ubuntu3.10_amd64.so");
    if !libc.exists() {
        return; // 该版本不在测试集时跳过
    }
    let pretty = run_rog(&libc, 1);
    let raw = Command::new(env!("CARGO_BIN_EXE_rog"))
        .arg(&libc)
        .arg("-l")
        .arg("1")
        .arg("--raw")
        .output()
        .expect("run rog --raw");
    let raw = String::from_utf8(raw.stdout).expect("utf8");
    let pretty_offsets: Vec<String> = pretty
        .lines()
        .filter(|l| l.starts_with("0x"))
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect();
    // master --raw 输出十进制偏移；pretty 输出十六进制 —— 数值应一致
    let raw_offsets: Vec<String> = raw
        .split_whitespace()
        .map(|d| format!("{:#x}", d.parse::<u64>().expect("decimal offset")))
        .collect();
    assert_eq!(pretty_offsets, raw_offsets, "pretty vs raw offsets diverge");
}
