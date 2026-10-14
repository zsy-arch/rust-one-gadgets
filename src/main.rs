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

    /// 开发用：arm textgen 与 master objdump 行流比对（FILE 为窗口 GT 文件目录）
    #[arg(long = "arm-gt-check", hide = true)]
    arm_gt_check: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.arm_gt_check {
        arm_gt_check(&cli.file.clone().unwrap_or_default());
        return;
    }

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
    // trim（去重/子集剔除）只属于扫描路径——Ruby 里 DB gadgets 直接进 refine（1.10.0：
    // trim 在 Fetcher#from_file 内部，builds() 不经过
    let mut gadgets = if let Some(id) = &cli.build_id {
        let g = match builds::gadgets_by_prefix(id) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[OneGadget] {e}");
                std::process::exit(1);
            }
        };
        gadget::refine_gadgets(g, cli.level)
    } else {
        let file = cli.file.as_ref().unwrap();
        let g = if !cli.force_file {
            // 先试 build-id 数据库（除非 -f）；非 x86 架构无数据库条目，直接走扫描
            if let Some(g) = gadgets_from_file_via_build_id(file) {
                gadget::refine_gadgets(g, cli.level)
            } else {
                gadgets_from_file_scan(file, cli.level)
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

/// 数据库路径：读文件 build-id → 查内置库。None = 未命中（回落扫描）。
fn gadgets_from_file_via_build_id(file: &str) -> Option<Vec<gadget::Gadget>> {
    let data = std::fs::read(file).ok()?;
    let libc = elf::Libc::parse(data).ok()?;
    let bid = libc.build_id?;
    let g = builds::gadgets_by_build_id(&bid);
    if g.is_empty() { None } else { Some(g) }
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

/// 开发工具：arm textgen 输出与 /tmp/arm_gt 的 master objdump 行流逐行比对。
/// 用法：rog --arm-gt-check <libc文件>；GT 文件名 = <libc文件名>.txt。
#[allow(dead_code)]
fn arm_gt_check(file: &str) {
    use crate::textgen::arm::disassemble_range;
    let data = std::fs::read(file).unwrap();
    let libc = crate::elf::Libc::parse(data).unwrap();
    let gt_file = format!(
        "/tmp/arm_gt/{}.txt",
        std::path::Path::new(file)
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
    );
    let gt: Vec<(bool, String)> = std::fs::read_to_string(&gt_file)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| match l.strip_prefix('W') {
            Some(r) => (true, r.to_string()),
            None => (false, l.trim_start().to_string()),
        })
        .collect();
    let mut windows: Vec<Vec<String>> = vec![];
    for (is_start, line) in gt {
        if is_start {
            windows.push(vec![]);
        }
        windows.last_mut().unwrap().push(line);
    }
    let mut bad = 0usize;
    let mut shown = 0usize;
    let mut total = 0usize;
    for w in &windows {
        let first_addr = u64::from_str_radix(w[0].split(':').next().unwrap(), 16).unwrap();
        let last_addr =
            u64::from_str_radix(w.last().unwrap().split(':').next().unwrap(), 16).unwrap();
        let mut bounds: Vec<u64> = vec![first_addr];
        for &(a, _) in &libc.arm_isa_chunks {
            if a > first_addr && a <= last_addr {
                bounds.push(a);
            }
        }
        bounds.sort_unstable();
        bounds.dedup();
        let mut got: Vec<String> = Vec::new();
        for pair in bounds.windows(2) {
            got.extend(disassemble_range(&libc, pair[0], pair[1]).into_iter().map(|l| l.text));
        }
        // 末段 hi：GT 末行是 OOB 标记 → 原窗口 stop 切在标记地址 +2（宽指令跨界）；
        // 否则 stop ≥ 最后一条完整指令尾 → +4
        let tail = if w.last().map(|l| l.contains("is out of bounds")).unwrap_or(false) {
            2
        } else {
            4
        };
        got.extend(
            disassemble_range(&libc, *bounds.last().unwrap(), last_addr + tail)
                .into_iter()
                .map(|l| l.text),
        );
        total += w.len();
        // 尾部可能多解码 1-2 行（last+4 过冲）；按 min(len) 比对
        for (g, want) in got.iter().zip(w.iter()) {
            if g != want {
                bad += 1;
                if shown < 10 {
                    println!("WANT: {want}\n GOT: {g}\n");
                    shown += 1;
                }
            }
        }
        if got.len() != w.len() {
            println!("LEN: got {} want {}", got.len(), w.len());
        }
    }
    println!("TOTAL {bad}/{total} ({:.3}% bad)", bad as f64 * 100.0 / total as f64);
}
