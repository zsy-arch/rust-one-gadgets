//! aarch64 textgen：yaxpeax-arm 解码 → objdump 兼容行。
//!
//! 关键对齐（GNU objdump aarch64）：
//! - `adrp x0, 3d000 <_fdata+...>`（页绝对地址 + 符号注释）
//! - `bl 3f288 <execve>`（绝对目标）
//! - `b.ne 4a200 <foo>`（绝对目标）
//! - `cbz x0, 9cecc` / `tbz w0, #4, ...`
//! - 立即数 `#` 前缀（objdump 打 `#0x10`；模拟器 strip 处理）
//!
//! textgen 输出直接作为模拟器输入；模拟器只依赖：
//! mnemonic（首 token）、操作数（逗号切分）、行地址、分支目标绝对地址、
//! call 行 `<name>` 尾注。符号注释可选（nearest_symbol 提供更佳渲染，非必需）。

use crate::elf::Libc;
use yaxpeax_arm::armv8::a64::InstDecoder;
use yaxpeax_arch::Decoder;

/// 反汇编 [lo, hi) 地址范围：4 字节步进，LE word。
/// 行格式 `"{addr:x}: {text}"`（与 objdump -d 单行一致）。
pub fn disassemble_range(libc: &Libc, lo: u64, hi: u64) -> Vec<String> {
    let decoder: InstDecoder = Default::default();
    let mut out = Vec::new();
    let mut addr = lo & !3;
    while addr < hi {
        let Some(bytes) = libc.bytes_at_vaddr(addr, 4) else { break };
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if let Some(text) = decode_line(&decoder, addr, word, libc) {
            out.push(format!("{addr:x}: {text}"));
        }
        addr += 4;
    }
    out
}

impl Libc {
    /// 符号注释：`nearest_symbol`（空 → None）。
    fn sym_at(&self, addr: u64) -> Option<String> {
        let s = self.nearest_symbol(addr);
        (!s.is_empty()).then_some(s)
    }
}

/// 解码一条指令为 objdump 风格行；None = 无法解码（bad word）。
pub fn decode_line(
    decoder: &InstDecoder,
    addr: u64,
    word: u32,
    libc: &Libc,
) -> Option<String> {
    let bytes = word.to_le_bytes();
    let mut inst = Default::default();
    let mut reader = yaxpeax_arch::U8Reader::new(&bytes);
    decoder.decode_into(&mut inst, &mut reader).ok()?;
    Some(render(&inst.to_string(), addr, &|t| libc.sym_at(t)))
}

/// yaxpeax 文本 → objdump 兼容文本（`$+off`/`$-off`/`$` → 绝对地址[ + 符号]）。
fn render(text: &str, addr: u64, symbolize: &dyn Fn(u64) -> Option<String>) -> String {
    let (mnem, rest) = match text.find(' ') {
        Some(i) => (&text[..i], &text[i + 1..]),
        None => (text, ""),
    };
    // adrp 的 $off 以「PC 所在页」为基（imm 已页对齐）；其余以 PC 为基
    let pc_base = if mnem == "adrp" { addr & !0xfff } else { addr };
    let bytes = rest.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            // 取相对偏移：[+/-]0x?[0-9a-f]*
            let mut j = i + 1;
            let rel_start = j;
            if j < bytes.len() && (bytes[j] == b'+' || bytes[j] == b'-') {
                j += 1;
            }
            if j + 1 < bytes.len() && bytes[j] == b'0' && bytes[j + 1] == b'x' {
                j += 2;
            }
            let digits_start = j;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            let rel: i64 = if j > digits_start || j > rel_start + 1 {
                crate::lambda::parse_int_str(&rest[rel_start..j]).unwrap_or(0)
            } else {
                0
            };
            let target = (pc_base as i64).wrapping_add(rel) as u64 & 0xffffffffffff;
            match symbolize(target) {
                Some(sym) => out.push_str(&format!("{target:x} <{sym}>")),
                None => out.push_str(&format!("{target:x}")),
            }
            i = j;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    if rest.is_empty() {
        mnem.to_string()
    } else {
        format!("{mnem} {out}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_range_real_sample() {
        // 顺带验证 adrp 渲染为页对齐绝对地址（objdump: `adrp x0, 0x127000`）

        // 样本集真机 e2e：BL execve 行必须带 <execve> 尾注（call 判定依赖）
        let Some(p) = crate::search21::samples_libc_path("glibc/aarch64/libc-2.27.so") else {
            eprintln!("sample missing — skipping");
            return;
        };
        let Ok(data) = std::fs::read(&p) else {
            eprintln!("sample missing: {} — skipping", p.display());
            return;
        };
        let libc = crate::elf::Libc::parse(data).unwrap();
        let lines = disassemble_range(&libc, 0x3f1c0, 0x3f1e0);
        assert!(lines.iter().any(|l| l.contains("bl a2b60 <execve")), "{lines:?}");
        let adrp = disassemble_range(&libc, 0x3f1b4, 0x3f1b8);
        eprintln!("adrp line: {adrp:?}");
        assert!(adrp[0].contains("127000"), "adrp page wrong: {adrp:?}");
    }

    fn no_sym(_: u64) -> Option<String> {
        None
    }

    /// decode_line 无符号版（测试：绕过 Libc）。
    fn render_decode(decoder: &InstDecoder, addr: u64, word: u32) -> Option<String> {
        let bytes = word.to_le_bytes();
        let mut inst = Default::default();
        let mut reader = yaxpeax_arch::U8Reader::new(&bytes);
        decoder.decode_into(&mut inst, &mut reader).ok()?;
        Some(render(&inst.to_string(), addr, &no_sym))
    }

    #[test]
    fn test_render_bl() {
        // bl $+0x84 at 0x1000 → 1084
        assert_eq!(render("bl $+0x84", 0x1000, &no_sym), "bl 1084");
    }

    #[test]
    fn test_render_bne() {
        assert_eq!(render("b.ne $+0x48", 0x4a1d0, &no_sym), "b.ne 4a218");
        assert_eq!(render("b.ne $-0x10", 0x4a1d0, &no_sym), "b.ne 4a1c0");
    }

    #[test]
    fn test_render_adrp() {
        // adrp 相对页：$+0x140000 基于 page(0x273a8)=0x27000 → 0x167000
        assert_eq!(render("adrp x0, $+0x140000", 0x273a8, &no_sym), "adrp x0, 167000");
    }

    #[test]
    fn test_decode_str() {
        let decoder: InstDecoder = Default::default();
        // str w0, [x0, #0xb7c]
        let line = render_decode(&decoder, 0x1000, 0xb90b7c00).unwrap();
        assert!(line.contains("str w0, [x0"), "{line}");
    }

    #[test]
    fn test_decode_bl_execve_site() {
        let decoder: InstDecoder = Default::default();
        // 2.27 do_system: bl 3f240 <execve> 编码 0x9400084d（site 0x3f288, target 0x61...）
        // 用相对验证：bl $+0x84 → word 0x94000021
        let line = render_decode(&decoder, 0x1000, 0x94000021).unwrap();
        assert_eq!(line, "bl 1084");
    }
}
