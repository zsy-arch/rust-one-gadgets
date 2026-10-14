//! `--near`：按 gadget 与给定函数的距离排序输出。
//!
//! 1.10.0 语义（cli.rb handle_near + helper.rb）：
//! - near 参数是逗号分隔函数列表，或一个 ELF 文件路径（取其 GOT 引用的函数集）
//! - 函数偏移来自 **libc 的动态符号表**（Ruby 用 objdump -T + 单词边界 grep）
//! - 输出：每函数一段，gadgets 按 |offset − func_offset| 升序
//! - GOT 函数集：目标 ELF 的 `.dynamic` DT_NEEDED 无关，直接取
//!   objdump -T 输出里带 `GLIBC_x.y` 版本标记的符号名集合

use crate::elf::Libc;
use crate::gadget::Gadget;

/// near 的一个分组：{ near, near_offset, gadgets }。
#[derive(serde::Serialize)]
pub struct NearGroup {
    pub near: String,
    pub near_offset: u64,
    pub gadgets: Vec<Gadget>,
}

/// 解析 near 参数 → 函数偏移分组。
///
/// `near_arg`：`printf,scanf,free` 或 ELF 文件路径（取 GOT 函数）。
/// 找不到任何函数时返回空（CLI 报 "No functions for processing"）。
pub fn collection(libc: &Libc, near_arg: &str, gadgets: &[Gadget]) -> Vec<NearGroup> {
    // ELF 文件 → GOT 函数集（其 dynsym 里 GLIBC 版本标记的导入函数）
    let functions: Vec<String> = if let Ok(data) = std::fs::read(near_arg) {
        match crate::elf::Libc::parse(data) {
            Ok(target) => got_functions(&target),
            Err(_) => near_arg.split(',').map(|s| s.trim().to_string()).collect(),
        }
    } else {
        near_arg.split(',').map(|s| s.trim().to_string()).collect()
    };

    // 函数名 → libc 偏移（动态符号表；同名多版本取第一个——对齐 objdump -T 首行）
    let mut out = Vec::new();
    for f in &functions {
        if f.is_empty() {
            continue;
        }
        if let Some(off) = libc.function_offset(f) {
            let mut sorted: Vec<Gadget> = gadgets.to_vec();
            sorted.sort_by_key(|g| g.offset.abs_diff(off));
            out.push(NearGroup { near: f.clone(), near_offset: off, gadgets: sorted });
        }
    }
    out
}

/// ELF 的 GOT 引用函数集：dynsym 中带 GLIBC_ 版本的**未定义**符号
/// （objdump -T 里显示为 `*UND* ... GLIBC_2.2.5 funcname` 行）。
fn got_functions(target: &Libc) -> Vec<String> {
    target.imported_glibc_functions()
}
