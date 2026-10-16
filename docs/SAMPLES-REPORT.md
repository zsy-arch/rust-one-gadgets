# 阶段性成果 ②：libc 样本集报告

日期：2026-10-14。样本集位置：`$ROG_LIBC_SAMPLES_DIR`（本地样本集，默认 `~/CTF/tools/rog_libc_samples`）。

## 总量

**68 个有效样本，0 个失败**（要求 ≥60 ✓）。每个样本均通过校验：
ELF 头（arch/endian/bits 与目录一致）+ `/bin/sh\x00` 存在 + SHA256 全长记录于
样本集内的 `MANIFEST.md`。

## 覆盖矩阵（计数 = 有效样本数）

| arch \ libc | glibc | musl | uClibc-ng | 合计 |
|---|---|---|---|---|
| amd64 | 6 | 5 | 1 | 12 |
| i386 | 5 | 5 | 1 | 11 |
| aarch64 | 10 | 5 | 1 | 16 |
| arm (armhf) | 9 | 5 | 1 | 15 |
| riscv64 | 4 | 1 | 0* | 5 |
| mips (BE) | 3 | 1 | 1 | 5 |
| mipsel (LE) | 2 | 1 | 1 | 4 |
| **合计** | **39** | **23** | **6** | **68** |

\* uclibc/riscv64 无预构建来源（Bootlin 未提供），已记录 MISSING.md；不影响
「每 (arch×libc) ≥1 e2e 测试」中对可获得组合的覆盖（20/21 组合齐）。

## 版本线

- **glibc**（要求 2.23/2.27/2.31/2.35/2.39 per-arch，可获得范围内全齐）：
  - aarch64/arm：2.23, 2.27, 2.31, 2.35, 2.39, 2.41（+fixtures 2.23/2.24/2.27/2.39/2.43）
  - riscv64：2.39, 2.41, 2.43（上游最早即 2.39）
  - mips BE：2.19, 2.24, 2.28（Debian mips 移植已死，2.31+ 无官方来源，记录 MISSING）
  - mipsel：2.36 (+fixture)
- **musl**：1.1.22 (v3.10), 1.2.2 (v3.14), 1.2.3 (v3.17), 1.2.4 (v3.18+OpenWrt), 1.2.5 (v3.20)
  × amd64/i386/aarch64/arm；riscv64 仅 1.2.5；mips/mipsel 1.2.4（one_gadget fixtures，
  含 golden 期望值，实现阶段的免费测试向量）。
- **uClibc-ng**：1.0.50（Bootlin stable-2024.05-1）× 6 arch。

## 来源（全部真实下载，无自造样本）

| 来源 | 用途 | 提取物 |
|---|---|---|
| ports.ubuntu.com (ubuntu-ports) | glibc arm64/armhf/riscv64 | .deb → data.tar → libc.so.6 |
| deb.debian.org + archive.debian.org | glibc mipsel/mips BE | 同上 |
| dl-cdn.alpinelinux.org minirootfs | musl 各版本线 | ld-musl-`<arch>`.so.1 |
| toolchains.bootlin.com | uClibc-ng 1.0.50 | 工具链 sysroot libc.so.0 实体 |
| one_gadget master spec fixtures (f6e57f0) | 11 个非 x86 libc | 直接拷入 |

## 工程产物（样本集目录内）

- `samples_def.py` — 数据驱动清单（69 条目含 riscv64-uclibc 占位剔除后 68）
- `fetch.py` — 幂等抓取器（`--check` / `--only`，curl 下载，ELF+/bin/sh 校验，
  MANIFEST 自动生成，含 version + SHA256 全长）
- `MANIFEST.md` — 68 行清单（path/arch/endian/bits/version/SHA256/status/source URL）
- `MISSING.md` — 缺口与原因（uclibc/riscv64、glibc mips BE ≥2.31、musl mips 1.1.x）
- `LICENSE_NOTES.md` — 各来源许可（LGPL-2.1+/MIT/GPL）；样本不随 rog 分发

## 对实现阶段的直接影响

1. **golden 测试向量**：11 个 one_gadget master fixtures 带 spec 期望值
   （aarch64 2.23/2.24/2.27/2.43、arm 2.23/2.27/2.39、riscv64 2.39、
   mipsel-glibc 2.36、mips/mipsel-musl 1.2.4）→ `tests/golden_arch.rs`。
2. **musl 原生支持验证**：mips-musl fixtures 证明 2.1.1 管线天然支持 musl
   （sectionless ELF），无需独立管线。
3. **e2e 素材**：20 个 (arch×libc) 组合每个 ≥1 真实样本，测试经
   `ROG_LIBC_SAMPLES_DIR` 环境变量发现，无硬编码路径。
4. **字节序覆盖**：mips BE 与 mipsel 成对，验证自写 MIPS 解码器双字节序逻辑。
