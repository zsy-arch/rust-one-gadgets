# rog

[one_gadget](https://github.com/david942j/one_gadget) 的高性能 Rust 重写 ——
在 glibc 里找 `execve("/bin/sh", ...)` / `posix_spawn("/bin/sh", ...)` gadget。

与 one_gadget **v1.10.0** 逐字节兼容（输出、顺序、格式完全一致），快 **~22×**，
单二进制零依赖（不需要 Ruby / objdump）。

```
$ rog libc-2.35-0ubuntu3.14_amd64.so -l 1
0x50a39 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  address rsp+0x70 is writable
  rsp & 0xf == 0
  {"sh", "-c", rbx, NULL} is a valid argv
  rbp == NULL || (u16)[rbp] == NULL
...
```

## 安装 / 构建

```bash
cargo build --release            # 当前平台
# Linux 静态（跨平台发布用）
RUSTFLAGS="-C linker=rust-lld" cargo build --release --target x86_64-unknown-linux-musl
```

平台支持：macOS（arm64/x86_64）、Linux（x86_64/aarch64 musl 静态）。
输入支持 **x86-64 (amd64) 与 i386** glibc。

## 用法

```
rog [FILE | -b BuildID] [OPTIONS]

Options:
  -b, --build-id <ID>    从内置 build-id 数据库查 gadget（支持唯一前缀）
  -f, --force-file       给 FILE 时跳过数据库，强制全量扫描
      --info <ID>        显示 BuildID 对应 libc 的版本信息
  -n, --near <FUNCS|F>   按与函数（printf,scanf 或 ELF 文件）的距离排序
  -s, --script <CMD>     对每个 gadget 执行 `CMD <offset>`
  -l, --level <LEVEL>    输出等级：0 = 仅最高概率（默认），1+ = 全部 [default: 0]
  -r, --raw              只输出偏移（空格分隔）
  -o, --output <FORMAT>  pretty | raw | json [default: pretty]
      --base <BASE>      偏移加基址输出
  -h, --help
  -V, --version
```

常见用法：

```bash
rog libc.so.6                    # build-id 命中数据库 → 预构建结果；否则扫描
rog libc.so.6 -f                 # 跳过数据库，强制扫描
rog libc.so.6 -l 1               # 全部
rog libc.so.6 -r                 # 只给偏移（脚本用）
rog libc.so.6 -l 1 --base 0x7f0000000000
rog -b 3bbdc31d                  # 只给 build-id（唯一前缀即可）
rog --info 3bbdc31d              # 该 build 的 libc 版本信息
rog --near printf,system libc.so.6 -l 1     # 按函数距离排序
rog --near /path/to/binary libc.so.6        # 取 binary 的 GOT 函数集
rog -s './try.sh' libc.so.6      # 逐 gadget 试 exploit
```

`ROG_TIME=1` 环境变量输出分段耗时（read+parse / disasm / search）。

### gadget 来源优先级（对齐 one_gadget）

给 FILE 时先读 ELF 的 `NT_GNU_BUILD_ID`，命中**内置数据库**（859 个上游
预构建结果，编译期嵌入二进制）就直接用；`-f` 跳过。`-b ID` 则完全走数据库。

## 性能

同 Docker 容器（arm64）、36 个 Ubuntu glibc（amd64 + i386，2.23–2.43）、
`-l 1` 全量扫描（`-f`）：

| 工具 | 总耗时 | 单文件 |
|---|---|---|
| one_gadget 1.10.0 (Ruby) | 19600 ms | 544 ms |
| **rog**（musl 静态） | **884 ms** | **25 ms** |

**~22× 加速**（目标 ≥10×）。macOS 原生（Apple Silicon）约 18 ms/文件
（数据库命中路径 <1 ms）。

来源：one_gadget 每次都要起 Ruby 解释器 + 全量 objdump 子进程 + 文本 grep；
rog 单进程完成 ELF 解析（goblin）→ iced-x86 全量**解码**（objdump 风格行文本
仅在候选窗口按需渲染）→ 符号模拟。

## 正确性

- **golden 回归测试**（`tests/golden.rs`）：36 个 libc（amd64 + i386）×
  level 0/1/2 共 **108 组**输出与 one_gadget v1.10.0 **逐字节一致**
  （含约束文本、顺序、空行）。
- **CLI 特性测试**（`tests/cli.rs`）：build-id 数据库、`--info`、`--near`、
  `-f`、`--script`、json 输出。
- 40+ 单元测试覆盖 Lambda 解析/渲染、模拟器指令语义（双架构）、评分与过滤。
- 已在 macOS arm64、Linux x86_64（musl）、Linux aarch64（musl）上验证；
  容器内与 gem 1.10.0 做 108 组对照全部一致。

```bash
cargo test          # 单元 + golden + cli（testdata 需在仓库内）
```

## 架构

```
elf (goblin: 段/符号/版本符号/bin_sh/build-id/PLTGOT)
 → disasm (iced-x86 解码元数据; objdump 行文本按需渲染; 32/64 位)
 → search (grep -B30 基本块 + amd64 jmp_case 候选; i386 rel_sh 过滤)
 → emulator (13 条指令符号执行; Lambda 值; sp/bp 栈表; amd64/i386)
 → resolver (execve/execl/posix_spawn 参数 → 约束; i386 GOT 基寄存器)
 → builds (内置 859 条 build-id 数据库, -b/--info/文件优先路径)
 → near (--near 函数距离排序 / ELF GOT 函数集)
 → gadget (trim 去重/剔除超集/排序 → level 过滤 → pretty/raw/json)
```

详细设计（含与 one_gadget 1.10.0 的语义对齐细节、已知陷阱）：
[docs/DESIGN.md](docs/DESIGN.md)

## 与 one_gadget 的差异

- 远程 build-id 数据库更新提示（gem 的 `ask_update`）不做，仅用内置 859 条。
- `--near` 的函数偏移取自 ELF 符号表而非 `objdump -T` 子进程（结果一致）。
- 版本锁定 1.10.0 语义（更新版本的 one_gadget 输出未对齐）。

## License

MIT
