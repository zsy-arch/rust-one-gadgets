//! rog —— one_gadget 的高性能 Rust 重写（语义对齐 v1.10.0）。
//!
//! 流水线：ELF 解析 → 全量解码（文本按需渲染）→ 候选窗口
//! （grep -B30/jmp_case 语义）→ 逐后缀符号执行 → 参数解析 →
//! 评分/level 过滤 → 输出。
//!
//! gadget 来源（对齐 1.10.0）：
//! - `-b/--build-id`：内置 build-id 数据库（859 条）
//! - 给文件：先查 build-id 命中数据库（`-f/--force-file` 跳过），否则全量扫描
//!
//! `ROG_TIME=1` 输出分段耗时（性能调优用）。

mod abi;
mod builds;
mod disasm;
mod elf;
mod emulator;
mod emulator21;
mod error;
mod gadget;
mod gadget21;
mod lambda;
mod near;
mod resolver;
mod resolve21;
mod search;
mod search21;
mod textgen;

use clap::Parser;

#[derive(Parser)]
#[command(name = "rog", version, about = "one_gadget in Rust — fast & cross-platform")]
struct Cli {
    /// libc 文件路径
    file: Option<String>,

    /// BuildID（sha1，支持唯一前缀）——与 FILE 互斥
    #[arg(short = 'b', long = "build-id")]
    build_id: Option<String>,

    /// 给 FILE 时跳过 build-id 数据库查询，强制全量扫描
    #[arg(short = 'f', long = "force-file")]
    force_file: bool,

    /// 显示 BuildID 对应的 libc 版本信息（来自数据库文件头注释）
    #[arg(long = "info")]
    info: Option<String>,

    /// 按与给定函数（printf,scanf 或 ELF 文件）的距离排序输出 gadgets
    #[arg(short = 'n', long = "near")]
    near: Option<String>,

    /// 对每个 gadget 执行 `script <offset>`
    #[arg(short = 's', long = "script")]
    script: Option<String>,

    /// 输出等级（0 = 仅最高概率，1+ = 全部）
    #[arg(short, long, default_value_t = 0)]
    level: u32,

    /// 只输出偏移（空格分隔）
    #[arg(short, long)]
    raw: bool,

    /// 输出格式 pretty|raw|json
    #[arg(short = 'o', long, default_value = "pretty")]
    output_format: String,

    /// libc 基址
    #[arg(long, default_value_t = 0)]
    base: u64,

}

fn main() {
    let cli = Cli::parse();

    // --info BuildID：打印数据库注释后退出
    if let Some(id) = &cli.info {
        match builds::info(id) {
            Ok(comments) => {
                println!("[OneGadget] Information of {id}:");
                println!("{}", comments.join("\n"));
            }
            Err(e) => {
                eprintln!("[OneGadget] {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if cli.file.is_some() && cli.build_id.is_some() {
        eprintln!("[OneGadget] Either FILE or BuildID can be passed");
        std::process::exit(1);
    }
    if cli.file.is_none() && cli.build_id.is_none() {
        eprintln!("Usage: rog <FILE|-b BuildID> [options] (--help for details)");
        std::process::exit(1);
    }

    // 取 gadgets（build-id 数据库 / 文件扫描两条路径）。
    // trim（去重/子集剔除）只属于扫描路径——Ruby 里 DB gadgets 直接进 refine。
    // 双代：x86 条目=1.10.0 快照（gadget::refine）；非 x86 条目=master 2.1.1
    // builds（gadget21::for_level + refine——DB 存全量，trim/all 按 level）。
    let mut gadgets = if let Some(id) = &cli.build_id {
        // -b 走数据库：无文件可检，不标置信度
        let (g, is21) = match builds::gadgets_by_prefix(id) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[OneGadget] {e}");
                std::process::exit(1);
            }
        };
        if is21 {
            gadget21::refine_gadgets(gadget21::for_level(g, cli.level), cli.level)
        } else {
            gadget::refine_gadgets(g, cli.level)
        }
    } else {
        let file = cli.file.as_ref().unwrap();
        // 非 glibc 检测（musl/uClibc-ng）：扫描结果基于 glibc 布局假设的
        // 启发式外推——stderr 标注置信度提醒（stdout 不动，保持与基准输出
        // 逐字节可比）。
        warn_non_glibc(file);
        let g = if !cli.force_file {
            // 先试 build-id 数据库（除非 -f）；未命中回落全量扫描。
            // 非 x86 条目：master 2.1.1 语义（for_level + refine）。
            // 另 master 对 level >= RAW_LEVEL(2) 强制扫描（DB 只存 trim 后全集，
            // l2 要 every gadget——"this emulates the file, bypassing the db"）。
            let via_db = if cli.level >= 2 {
                None
            } else {
                gadgets_from_file_via_build_id(file)
            };
            match via_db {
                Some((g, true)) => gadget21::refine_gadgets(gadget21::for_level(g, cli.level), cli.level),
                Some((g, false)) => gadget::refine_gadgets(g, cli.level),
                None => gadgets_from_file_scan(file, cli.level),
            }
        } else {
            gadgets_from_file_scan(file, cli.level)
        };
        g
    };
    for g in &mut gadgets {
        g.base = cli.base;
    }

    // --script：每个 gadget 跑一次 `script <offset>`
    if let Some(script) = &cli.script {
        for g in &gadgets {
            eprintln!("[OneGadget] Trying {:#x}...", g.offset);
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("{script} {:#x}", g.offset))
                .status();
        }
        return;
    }

    // --near：需要 libc 文件（函数偏移查它的符号表）
    if let Some(near_arg) = &cli.near {
        let Some(file) = &cli.file else {
            eprintln!("[OneGadget] Libc file must be given when using --near option");
            std::process::exit(1);
        };
        let data = std::fs::read(file).unwrap_or_else(|e| {
            eprintln!("rog: cannot read {file}: {e}");
            std::process::exit(1);
        });
        let libc = elf::Libc::parse(data).unwrap_or_else(|e| {
            eprintln!("rog: {e}");
            std::process::exit(1);
        });
        let coll = near::collection(&libc, near_arg, &gadgets);
        if coll.is_empty() {
            eprintln!("[OneGadget] No functions for processing");
            std::process::exit(1);
        }
        if cli.output_format == "json" {
            println!("{}", serde_json::to_string_pretty(&coll).unwrap_or_default());
        } else {
            for c in &coll {
                eprintln!("[OneGadget] Gadgets near {}({:#x}):", c.near, c.near_offset);
                display_gadgets(&c.gadgets, &cli);
                println!();
            }
        }
        return;
    }

    display_gadgets(&gadgets, &cli);
}

/// 非 glibc 检测：读文件前 1MB 找 musl/uClibc 标记串（musl 的 SONAME 串
/// `libc.musl-<arch>.so.1` 与 `MUSL_LOCPATH`；uClibc 的 `__uClibc_main`）。
/// 命中则 stderr 提示启发式置信度。glibc 不含任何标记。
fn warn_non_glibc(file: &str) {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(file) else { return };
    let mut buf = vec![0u8; 0x10_0000.min({
        let len = f.metadata().map(|m| m.len()).unwrap_or(0x10_0000);
        len.max(1) as usize
    })];
    let Ok(n) = f.read(&mut buf) else { return };
    let haystack = &buf[..n];
    let flavor = if contains_sub(haystack, b"libc.musl-")
        || contains_sub(haystack, b"MUSL_LOCPATH")
        || contains_sub(haystack, b"musl libc (")
    {
        Some("musl")
    } else if contains_sub(haystack, b"__uClibc_main") {
        Some("uClibc")
    } else {
        None
    };
    if let Some(fl) = flavor {
        eprintln!(
            "[OneGadget] Note: {fl} libc detected; gadgets are heuristic \
             (semantics extrapolated from glibc) — verify constraints before use."
        );
    }
}

/// 无 std 子串搜索（&[u8] windows 匹配）。
fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// 数据库路径：读文件 build-id → 查内置库。None = 未命中（回落扫描）。
/// 返回 (gadgets, 是否 2.1.1 语义条目)。
fn gadgets_from_file_via_build_id(file: &str) -> Option<(Vec<gadget::Gadget>, bool)> {
    let data = std::fs::read(file).ok()?;
    let libc = elf::Libc::parse(data).ok()?;
    let bid = libc.build_id?;
    let (g, is21) = builds::gadgets_by_build_id(&bid);
    if g.is_empty() { None } else { Some((g, is21)) }
}

/// 全量扫描路径（含 level 过滤：x86 → 1.10.0 语义，其余 → 2.1.1 语义）。
fn gadgets_from_file_scan(file: &str, level: u32) -> Vec<gadget::Gadget> {
    let t_start = std::time::Instant::now();
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("rog: cannot read {file}: {e}");
            std::process::exit(1);
        }
    };
    let libc = match elf::Libc::parse(data) {
        Ok(l) => std::sync::Arc::new(l),
        Err(e) => {
            eprintln!("rog: {e}");
            std::process::exit(1);
        }
    };
    // 非 x86：2.1.1 管线（search21，按架构适配器分派）
    if !matches!(libc.arch, elf::Arch::X64 | elf::Arch::X86) {
        let t = std::time::Instant::now();
        let found = match libc.arch {
            elf::Arch::Aarch64 => search21::Searcher::new(&libc, &search21::aarch64::Aarch64Search).find(),
            elf::Arch::Arm => search21::Searcher::new(&libc, &search21::arm::ArmSearch).find(),
            elf::Arch::Riscv64 => {
                search21::Searcher::new(&libc, &search21::riscv64::Riscv64Search).find()
            }
            elf::Arch::Mips => {
                search21::Searcher::new(&libc, &search21::mips::MipsSearch).find()
            }
            _ => {
                eprintln!("rog: arch {:?} not yet supported by search21", libc.arch);
                std::process::exit(1);
            }
        };
        // master 2.1.1：prune 已在 Gadget 构造器内 → for_level（trim/all）→ refine
        let gadgets = gadget21::refine_gadgets(gadget21::for_level(found, level), level);
        if std::env::var_os("ROG_TIME").is_some() {
            eprintln!("read+parse+search21: {:?} ({} gadgets)", t_start.elapsed(), gadgets.len());
        }
        let _ = t;
        return gadgets;
    }
    // 全量解码可执行段（只解码；objdump 行文本在候选窗口内按需渲染）
    let t = std::time::Instant::now();
    let seg = libc.executable_segment().expect("no exec segment");
    let insns = disasm::disassemble_range(&libc, seg.vaddr, seg.vaddr + seg.file_size);
    let t_disasm = t.elapsed();
    let t = std::time::Instant::now();
    let found = search::find(&libc, &insns);
    let t_search = t.elapsed();
    let gadgets = gadget::refine_gadgets(gadget::trim_gadgets(found), level);
    if std::env::var_os("ROG_TIME").is_some() {
        eprintln!(
            "read+parse: {:?}  disasm: {:?} ({} insns)  search: {:?}",
            t_start.elapsed() - t_disasm - t_search,
            t_disasm,
            insns.len(),
            t_search
        );
    }
    gadgets
}

/// 按输出格式渲染 gadget 列表（pretty/raw/json）。
fn display_gadgets(gadgets: &[gadget::Gadget], cli: &Cli) {
    match (cli.raw, cli.output_format.as_str()) {
        (true, _) | (false, "raw") => {
            // master：gadgets.map(&:value).join(' ') —— value 为十进制整数
            let vals: Vec<String> = gadgets.iter().map(|g| g.value().to_string()).collect();
            if !vals.is_empty() {
                println!("{}", vals.join(" "));
            }
        }
        (false, "json") => match serde_json::to_string_pretty(gadgets) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("rog: json error: {e}");
                std::process::exit(1);
            }
        },
        _ => {
            // CLI display_gadgets：map(&:inspect).join("\n")
            let out: Vec<String> = gadgets.iter().map(|g| g.to_pretty()).collect();
            if !out.is_empty() {
                print!("{}", out.join("\n"));
            }
        }
    }
}
