//! 新 CLI 特性测试：build-id 数据库、--info、--near、-f、--script。

use std::process::Command;

fn rog() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rog"))
}

fn run(args: &[&str]) -> (String, String, bool) {
    let out = rog().args(args).output().expect("run rog");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

/// 2.23-0ubuntu3_amd64 的 build-id（在 859 条内置库中）。
const BID_223: &str = "369de0e1d833caa693af17f17c83ba937f0a4dad";

#[test]
fn build_id_lookup_matches_file_db_path() {
    // -b 与「给文件且 DB 命中」两条路径给出同一组 gadgets
    let (b_out, _, ok) = run(&["-b", BID_223, "-l", "1", "-r"]);
    assert!(ok);
    let (f_out, _, ok2) = run(&["testdata/libc-2.23-0ubuntu3_amd64.so", "-l", "1", "-r"]);
    assert!(ok2);
    assert_eq!(b_out, f_out, "-b and file(DB-hit) must agree");
    assert!(!b_out.trim().is_empty());
}

#[test]
fn build_id_prefix_and_errors() {
    // 唯一前缀
    let (p_out, _, ok) = run(&["-b", "369de0e1d833", "-l", "1", "-r"]);
    assert!(ok);
    let (f_out, _, _) = run(&["-b", BID_223, "-l", "1", "-r"]);
    assert_eq!(p_out, f_out);
    // 不存在的 id
    let (_, err, ok) = run(&["-b", "ffffffff00000000feed", "-l", "1"]);
    assert!(!ok);
    assert!(err.contains("not found"), "err: {err}");
    // 文件 + build-id 互斥
    let (_, err, ok) = run(&["-b", BID_223, "testdata/libc-2.23-0ubuntu3_amd64.so"]);
    assert!(!ok);
    assert!(err.contains("Either FILE or BuildID"));
}

#[test]
fn force_file_overrides_db() {
    // 该测试 libc 恰好在内置库中（上游扫的就是同一文件），-f 与 DB 路径给出同一组
    let (scan, _, ok) = run(&["testdata/libc-2.23-0ubuntu3_amd64.so", "-f", "-l", "1", "-r"]);
    assert!(ok);
    // master --raw 输出十进制偏移（0x451ff = 283135）
    assert!(scan.contains("283135"), "-f must produce scan gadgets: {scan}");
    let (db, _, _) = run(&["testdata/libc-2.23-0ubuntu3_amd64.so", "-l", "1", "-r"]);
    assert_eq!(scan.trim(), db.trim(), "for this corpus build both paths must agree");
}

#[test]
fn info_build_id() {
    let (out, _, ok) = run(&["--info", "369de0e1d833"]);
    assert!(ok);
    assert!(out.contains("Information of 369de0e1d833"), "{out}");
    assert!(out.contains("Advanced Micro Devices X86-64"), "{out}");
    let (_, err, ok) = run(&["--info", "ffffffff00000000feed"]);
    assert!(!ok);
}

#[test]
fn near_functions_sort() {
    let (out, err, ok) = run(&[
        "--near", "printf,system",
        "testdata/libc-2.23-0ubuntu3_amd64.so",
        "-f", "-l", "1", "-r",
    ]);
    assert!(ok, "err: {err}");
    assert!(err.contains("Gadgets near printf(0x557b0)"), "err: {err}");
    assert!(err.contains("Gadgets near system(0x45380)"), "err: {err}");
    // 排序验证：printf@0x557b0 最近的是 0x4525a（|0x4525a-0x557b0| = 0x10556 最小）
    // master --raw 输出十进制（0x4525a = 283226）
    let first = out.lines().next().unwrap().split_whitespace().next().unwrap();
    assert_eq!(first, "283226");
}

#[test]
fn near_requires_libc_file() {
    let (_, err, ok) = run(&["-b", BID_223, "--near", "printf"]);
    assert!(!ok);
    assert!(err.contains("Libc file must be given"));
}

#[test]
fn script_runs_each_gadget() {
    // -l 0 + 脚本 echo：每 gadget 一行 Trying
    let (_, err, ok) = run(&[
        "-s", "echo hi",
        "testdata/libc-2.23-0ubuntu3_amd64.so",
        "-f",
    ]);
    assert!(ok);
    assert!(err.contains("Trying 0x"), "{err}");
}

#[test]
fn json_output_gadgets() {
    let (out, _, ok) = run(&["testdata/libc-2.23-0ubuntu3_amd64.so", "-f", "-l", "1", "-o", "json"]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert!(v.as_array().is_some_and(|a| !a.is_empty()));
    assert!(v[0]["offset"].is_u64());
    assert!(v[0]["effect"].as_str().is_some_and(|s| s.contains("execve")));
}
