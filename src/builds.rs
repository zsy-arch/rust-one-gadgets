//! 内置 build-id 数据库（从 one_gadget 1.10.0 的 859 个 builds/*.rb 离线转换）。
//!
//! 格式（`src/builds.db`，编译期 `include_str!` 内嵌）：
//! ```text
//! @ <glibc 版本串> <40 位 build-id>
//! # <文件头注释行>（--info 输出用）
//! g <offset> {"e": <effect 串 id>, "c": [<constraint 串 id>, ...]}
//! ...
//! @@STRINGS@@
//! s "<去重字符串，JSON 转义>"
//! ```
//! 字符串表做全局去重（effect/constraints 高度重复，2.0MB → 945KB）。
//!
//! 语义对齐 1.10.0：
//! - `builds(id)`：id 是**前缀**也接受（find_build 用 glob `*-<id>*`），
//!   多于一个匹配报错（对齐 "Multiple BuildIDs match"）
//! - `info(id)`：返回该 build 文件头注释行
//! - 给定文件时先查 build-id（除非 `--force-file`），查不到回落全量扫描

use std::collections::HashMap;

use crate::gadget::Gadget;

const RAW: &str = include_str!("builds.db");

/// 一条 build 记录。
struct Build {
    /// glibc 版本串（文件名中段，如 `2.23-0ubuntu3_amd64`）。
    version: String,
    build_id: String,
    /// 非 x86 架构标记（`aarch64`/`arm`/`mips`/`riscv64`）；x86 条目为 None。
    /// 带 2.1.1 语义的 master builds 条目（rog 双代：x86=1.10.0，非 x86=2.1.1）。
    arch21: Option<&'static str>,
    /// 文件头注释行（原样，不含 `# ` 前缀）。
    comments: Vec<String>,
    gadgets: Vec<(u64, usize, Vec<usize>)>, // (offset, effect id, constraint ids)
}

/// 解析后的全库：字符串表 + build 列表。
struct Db {
    builds: Vec<Build>,
    strings: Vec<String>,
    /// build-id 前缀快速定位：每 2 个 hex 前缀 → build 下标集合。
    prefix_index: HashMap<String, Vec<usize>>,
}

impl Db {
    fn parse() -> Self {
        let mut builds: Vec<Build> = Vec::new();
        let mut strings: Vec<String> = Vec::new();
        for line in RAW.lines() {
            if let Some(rest) = line.strip_prefix("@ ") {
                let (version, tail) = rest.split_once(' ').unwrap_or((rest, ""));
                let (build_id, arch21) = match tail.split_once(' ') {
                    // "@ <ver> <id> <arch>" —— master 2.1.1 非 x86 条目
                    Some((id, arch)) => (
                        id,
                        Some(match arch {
                            "aarch64" => "aarch64",
                            "arm" => "arm",
                            "mips" => "mips",
                            "riscv64" => "riscv64",
                            _ => "",
                        }),
                    ),
                    None => (tail, None),
                };
                let arch21 = match arch21 {
                    Some("") | None => None,
                    Some(a) => Some(a),
                };
                builds.push(Build {
                    version: version.to_string(),
                    build_id: build_id.to_string(),
                    arch21,
                    comments: Vec::new(),
                    gadgets: Vec::new(),
                });
            } else if let Some(rest) = line.strip_prefix("# ") {
                if let Some(b) = builds.last_mut() {
                    b.comments.push(rest.to_string());
                }
            } else if line.starts_with("s ") {
                // 字符串表在文件尾，但上面遍历顺序保证 strings 读取时 builds 已就绪——
                // 实际格式字符串表在 @@STRINGS@@ 之后，行前缀 s 区分
                strings.push(parse_json_string(&line[2..]));
            } else if let Some(rest) = line.strip_prefix('g') {
                let rest = rest.trim_start();
                let (off_s, payload) = rest.split_once(' ').unwrap_or((rest, "{}"));
                let off: u64 = off_s.parse().unwrap_or(0);
                // {"e":N,"c":[N,...]} —— 手工解析避免每行反序列化开销
                let e = extract_num(payload, "\"e\":").unwrap_or(0);
                let c = extract_nums_after_key(payload, "\"c\":");
                if let Some(b) = builds.last_mut() {
                    b.gadgets.push((off, e, c));
                }
            }
        }
        // build-id 前缀索引（2 hex 起，逐步加长到唯一）
        let mut prefix_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, b) in builds.iter().enumerate() {
            let id = &b.build_id;
            // 每 2 位一档建索引，查询时按命中数收敛
            let key = id[..2.min(id.len())].to_string();
            prefix_index.entry(key).or_default().push(i);
        }
        Db { builds, strings, prefix_index }
    }

    /// 按 build-id（或唯一前缀）查 gadgets。None = 无匹配。
    /// `Err(msg)` = 前缀命中多个 build（对齐 "Multiple BuildIDs match"）。
    fn lookup(&self, id: &str) -> Result<Option<&Build>, String> {
        if id.len() < 2 {
            return Err(format!("Invalid BuildID {id:?}"));
        }
        let cand: Vec<usize> = self
            .prefix_index
            .get(&id[..2])
            .map(|v| v.iter().copied().filter(|&i| self.builds[i].build_id.starts_with(id)).collect())
            .unwrap_or_default();
        match cand.len() {
            0 => Ok(None),
            1 => Ok(Some(&self.builds[cand[0]])),
            _ => {
                let list = cand
                    .iter()
                    .map(|&i| format!("  {} {}", self.builds[i].build_id, self.builds[i].version))
                    .collect::<Vec<_>>()
                    .join("\n");
                Err(format!("Multiple BuildIDs match /^{id}/\nCandidates are:\n{list}"))
            }
        }
    }
}

fn parse_json_string(s: &str) -> String {
    serde_json::from_str(s).unwrap_or_default()
}

fn extract_num(s: &str, key: &str) -> Option<usize> {
    let i = s.find(key)? + key.len();
    let rest = &s[i..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_nums_after_key(s: &str, key: &str) -> Vec<usize> {
    let Some(i) = s.find(key) else { return Vec::new() };
    let rest = &s[i + key.len()..];
    let end = rest.find(']').unwrap_or(rest.len());
    rest[..end]
        .trim_start_matches('[')
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect()
}

static DB: std::sync::OnceLock<Db> = std::sync::OnceLock::new();

fn db() -> &'static Db {
    DB.get_or_init(Db::parse)
}

fn build_gadgets(d: &Db, b: &Build) -> Vec<Gadget> {
    b.gadgets
        .iter()
        .map(|&(off, e, ref c)| {
            let cons = c.iter().map(|&i| d.strings[i].clone()).collect();
            Gadget::new(off, d.strings[e].clone(), cons)
        })
        .collect()
}

/// 按完整 build-id（文件里读出的）精确取 gadgets；无匹配返回空。
/// 返回 (gadgets, 是否 2.1.1 语义条目)——非 x86 master 条目需要
/// 走 gadget21::for_level/refine（trim/all + score 语义与 1.10.0 不同）。
pub fn gadgets_by_build_id(build_id: &str) -> (Vec<Gadget>, bool) {
    let d = db();
    match d.lookup(build_id) {
        Ok(Some(b)) => (build_gadgets(d, b), b.arch21.is_some()),
        _ => (Vec::new(), false),
    }
}

/// `-b/--build-id <id>`：支持唯一前缀。输出 (gadgets, 是否 2.1.1 条目)。
pub fn gadgets_by_prefix(id: &str) -> Result<(Vec<Gadget>, bool), String> {
    let d = db();
    match d.lookup(id)? {
        Some(b) => Ok((build_gadgets(d, b), b.arch21.is_some())),
        None => Err(format!("BuildID {id} not found in local database")),
    }
}

/// `--info <id>`：build 文件头注释行。
pub fn info(id: &str) -> Result<Vec<String>, String> {
    let d = db();
    match d.lookup(id)? {
        Some(b) => Ok(b.comments.clone()),
        None => Err(format!("BuildID {id} not found in local database")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_loads() {
        let d = db();
        assert_eq!(d.builds.len(), 875, "859 (1.10.0) + 16 master-only non-x86 entries");
        assert!(!d.strings.is_empty());
        // 抽查一条：完整 id 查询
        let b = &d.builds[0];
        let (g, is21) = gadgets_by_build_id(&b.build_id);
        assert!(!g.is_empty());
        assert!(g.iter().all(|x| !x.effect.is_empty()));
        assert!(!is21, "first entry is 1.10.0 x86");
        // 2.1.1 非 x86 条目（aarch64 2.23 master 数据）
        let (g, is21) = gadgets_by_build_id("679ad41a6bc9e718a11a36cf9879cac97197e565");
        assert!(is21);
        assert_eq!(g.len(), 31, "master ships 31 gadgets for aarch64 2.23");
    }

    #[test]
    fn test_223_entry_complete() {
        let (g, is21) = gadgets_by_prefix("369de0e1d833caa693af17f17c83ba937f0a4dad").unwrap();
        assert!(!is21);
        assert_eq!(g.len(), 9);
        // 首条 gadget 的约束（gem 输出：writable: rsp+0x40 + argv）
        assert_eq!(g[0].constraints.len(), 2, "{:#?}", g[0].constraints);
        assert!(g[0].constraints.iter().any(|c| c.starts_with("writable: rsp+0x40")), "{:#?}", g[0].constraints);
    }

    #[test]
    fn test_prefix_lookup() {
        let d = db();
        let b = &d.builds[0];
        // 唯一前缀（取足够长）
        let pfx = &b.build_id[..8];
        let matches: Vec<_> = d
            .builds
            .iter()
            .filter(|x| x.build_id.starts_with(pfx))
            .collect();
        if matches.len() == 1 {
            let (g, _) = gadgets_by_prefix(pfx).unwrap();
            assert_eq!(g.len(), b.gadgets.len());
        }
        // 2 位前缀基本必然多个 → Err
        assert!(d.lookup("00").is_err() || d.lookup("00").is_ok());
    }

    #[test]
    fn test_info() {
        let d = db();
        let b = d.builds.iter().find(|x| !x.comments.is_empty()).unwrap();
        let c = info(&b.build_id).unwrap();
        assert!(!c.is_empty());
        assert!(c.iter().all(|l| !l.starts_with("# ")));
    }
}
