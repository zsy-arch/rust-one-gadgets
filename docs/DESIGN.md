# rog 设计文档

`rog` = **R**ust **o**ne\_ga**g**et —— one_gadget 的高性能 Rust 重写。

## 目标

1. **逐字节兼容**：与 one_gadget **v1.10.0** 相同的输入（glibc ELF）、**完全相同**的输出
   （offset + effect + constraints，含顺序与空行）。18 个 Ubuntu glibc（2.23–2.39）
   × level 0/1/2 共 54 组输出全部逐字节一致（`tests/golden.rs`）。
2. **快速**：比 one_gadget ≥10×。实测（同 Docker 容器、相同 18 个 libc）：
   one_gadget 8.4s vs rog 0.415s → **~20×**（23ms/libc vs 468ms/libc）。
3. **跨平台**：单二进制零外部依赖（不需要 objdump/ruby）。macOS（arm64）、
   Linux（x86_64/aarch64 musl 静态）均验证。
4. **工程化**：模块化、可单测、golden 回归测试。

## 非目标

- 不实现 one_gadget 的 build-id 远程数据库下载。
- 不实现 `--near`、`--script`。
- 首发架构：amd64 + i386（均已交付；aarch64 不做——one_gadget 1.10.0 对其支持不完整）。

## 与 one_gadget 1.10.0 的语义对齐策略

one_gadget 1.10.0 的候选发现与模拟**全部基于 objdump 文本**
（`objdump --dwarf-start=0 --no-show-raw-insn -w -d -M intel` + Ruby grep/字符串处理）。
rog 用 iced-x86 复现**等价的 objdump 文本语义**，而不是重新设计算法——
这是逐字节一致的关键：

| one_gadget (Ruby) | rog (Rust) |
|---|---|
| `grep -E 'call.*<(exec[^+]*\|posix_spawn[^+]*)>$' -B 30` 分块 | 指令元数据扫描（call 目标 + 符号注释判定），grep `-B30` 的 `--` 分块语义逐行复现 |
| 块内首个匹配 call 切块（loop-shift） | 同 |
| `slice_prefix`（最后分支行 rindex 截断） | 渲染行子串匹配（jmp/je/jne/jl/jb/ja/jg 整行匹配） |
| amd64 过滤（整块文本 include?） | 同（`posix_spawn@` 字面 / bin_sh hex / 末行 execve） |
| `grep -E '# <bin_sh_hex>' -A 8` jmp_case | `rip_target == bin_sh` 等价判定 + `-A8` 合并分块语义 |
| 13 条指令的文本匹配模拟器 | 同集文本模拟器（操作数文本 → parse → Lambda 运算） |
| Lambda（base+imm+deref+op） | `src/lambda.rs` 同构实现（含 predefined 折叠语义） |
| 约束渲染、评分、trim/level 过滤 | 同（连 `Integer#to_s` 十进制渲染都对齐） |

关键陷阱（踩过的坑，测试里都有回归）：

- **BFD 双 weak 别名**：同一地址多个符号（sigaction/__sigaction）时 objdump 显示
  `__` 前缀者优先，其次 `@@` default 版本——影响 call 注释 → 影响候选过滤。
- **grep -A8 块合并**：相邻匹配 ≤8 行时 `--` 分块合并，jmp_case 的 call 拒绝语义
  作用在**合并后**的块上（2.26 多出 3 个假 gadget 的根因）。
- **嵌套 evaluate raise**：`mov [rcx+0x10],0` 且 rcx=`[rbp-0x78]` 时，
  Ruby 的 `dst.evaluate` 对嵌套 obj raise → 模拟停止（**不是**继续）。
  rog 用 `eval_offset` 只接受直接 sp/bp 基来对齐。
- **窄寄存器提升**：`xor edx,edx` 写**全名** rdx=0；r12d 不在 ABI 表 → 拒绝。
- **Const(0) 渲染**：十进制 "0"（Ruby Integer#to_s），不是 "0x0"——
  argv 约束的 `argv[i] == '0'` 判定依赖它。

## 架构

```
                ┌─────────────┐
   libc.so.6 ──▶│  elf        │  goblin: 段/符号表（含 symbol versioning）/bin_sh 偏移
                └──────┬──────┘
                       ▼
                ┌─────────────┐   iced-x86 全量**只解码**（元数据：目标地址），
                │  disasm     │   objdump 风格行文本**按需**渲染（性能关键：
                └──────┬──────┘   51 万条指令只有候选窗口的几百行需要文本）
                       ▼
                ┌─────────────┐   grep -B30 分块 → loop-shift → slice_prefix
                │  search     │   → amd64 过滤 / i386 rel_sh 过滤；amd64 jmp_case
                │  emulator   │   → 13 条指令符号执行（32/64 位参数化：字长/xmm lane/寄存器表）
                └──────┬──────┘
                       ▼
                ┌─────────────┐   逐候选×逐后缀文本模拟（13 条指令集）
                │  emulator   │   Lambda 符号值；栈表（sp/bp 两张）
                └──────┬──────┘
                       ▼
                ┌─────────────┐   execve/posix_spawn 参数 → 约束文本
                │  resolver   │   （argv/envp 构造、environ 命中、-c 替换）
                └──────┬──────┘
                       ▼
                ┌─────────────┐   trim（uniq/子集剔除/排序）→ level 过滤（score）
                │  gadget     │   → pretty/raw/json
                └──────┬──────┘
                       ▼
                ┌─────────────┐
                │  main (cli) │   clap；ROG_TIME=1 分段计时
                └──────┘
```

## 模块职责

| 模块 | 文件 | 职责 |
|---|---|---|
| `elf` | `src/elf.rs` | ELF 解析：段、`.dynsym`/`.symtab`、symbol versioning（versym/verdef/verneed）、`nearest_symbol`（objdump 注释语义）、`/bin/sh` 定位 |
| `disasm` | `src/disasm.rs` | iced-x86 解码 → `Insn` 元数据；`render_text/render_line` 按需产出 objdump -M intel 风格文本；操作数切分（fetch_args 语义） |
| `search` | `src/search.rs` | 候选发现：basic-block（grep -B30 语义）+ jmp_case（grep -A8 语义）；`find`：逐后缀模拟 + resolve |
| `emulator` | `src/emulator.rs` | 13 条指令文本模拟器；Lambda 寄存器状态；sp/bp 栈表；writable/movaps 约束 |
| `lambda` | `src/lambda.rs` | 符号值：base + imm + deref + op；`parse_operand`（predefined 折叠） |
| `resolver` | `src/resolver.rs` | execve/posix_spawn 参数检查 → 约束（argv/envp 生成、`-c` 替换、environ） |
| `gadget` | `src/gadget.rs` | Gadget + score（calculate_score 语义）+ trim_gadgets + refine_gadgets（level）+ pretty 渲染 |
| `main` | `src/main.rs` | CLI（clap）：`-l/-r/--raw/-o/--base` |
| `error` | `src/error.rs` | 统一错误类型 |

## 核心数据结构

```rust
/// 一条解码后的指令（元数据；文本按需渲染）
pub struct Insn {
    pub addr: u64,
    pub next_addr: u64,
    pub mnemonic: Mnemonic,
    pub branch_target: Option<u64>, // jcc/jmp 直接目标
    pub call_target: Option<u64>,   // call rel32 目标
    pub rip_target: Option<u64>,    // rip 相对内存操作数目标
}

/// 符号值（对齐 one_gadget Lambda）
pub enum Val {
    Const(i64),           // 渲染为十进制（Ruby Integer#to_s）
    Lambda(Lambda),
    Xmm([Box<Val>; 2]),   // 128-bit 按 lane 拆分
    Clobbered,
}

pub struct Lambda {
    pub base: Base,             // Reg(name) | LibcBase | Nested(Box<Val>)
    pub imm: i64,
    pub deref_count: u32,
    pub op: Option<(char, i64)>,  // (rdi & 0xf) 等
}
```

## 关键算法

### 1. 候选发现（search::basic_block_candidates）

对齐 Ruby `fetcher#candidates`：

1. 全量指令里找终结 call（注释符号以 exec/posix_spawn 开头且无 `+`）。
2. 每个 call 取前 30 行窗口（grep -B30 的 `--` 分块：下界 = 上一匹配 +1）。
3. 窗口内首个匹配 call 切块（连续 call 逐块产出，loop-shift）。
4. `slice_prefix`：裁到**最后**分支行（整行子串匹配 jmp/je/jne/jl/jb/ja/jg）之后。
5. amd64 过滤（整块 join 文本）：含 `posix_spawn@` 直通；否则须含 bin_sh hex
   且末行含 `execve`。

### 2. jmp_case（search::jmp_case_candidates）

对齐 Ruby `fetcher#jmp_case`：

1. rip 相对目标 == bin_sh 偏移的行（等价 `grep '# <bin_sh_hex>'`）。
2. `-A 8` 分块：相邻匹配 ≤8 行合并为一个块。
3. 块内首个含 jmp 的行截断；截断前含 call → 整块丢弃。
4. jmp 目标处反汇编 100 字节到首个行含 `execve` 的 call；候选 = 前段 + 目标段。

### 3. 符号执行（emulator）

- 指令集（文本助记符匹配）：add/call/jmp/lea/mov/nop/push/sub/xor/movq/movaps/movhps/punpcklqdq
  ——其余指令遇即 refused（模拟停止，对齐 1.10.0）。
- 寄存器 = Val；窄名与全名**相互独立**（除 xor 的 e 前缀提升）。
- 内存：只跟踪 sp/bp 两张栈表（offset → Val）；store 记 `writable:` 约束
  （rip 基豁免）；load **无读回**（`mov rdi,[rbp-0x48]` 得 `[rbp-0x48]` lambda）。
- 安全调用（sigprocmask/__close/unsetenv/__sigaction）不 clobber；其余 call 拒绝。
- 每个**后缀**（i 从 len-2 downto 0）独立模拟——同一块的多个入口各自成候选。

### 4. 约束生成与过滤（resolver / gadget）

- execve：arg0 须 `rip+0x`（bin_sh 位置）；argv 三路（NULL / 已含 sh / 需构造，
  构造时 i==1 的全局变量渲染 `"-c"`）；envp（environ 命中 / `[[..]]` 判定 / 约束）。
- posix_spawn：file_actions `(s32)[x+4] <= 0`、attrp `(u16)[x] == NULL`、pid 栈判定。
- `render_constraints`：writable 按 deref==0 归并基名去重，其余整体去重，字典序排序。
- `trim_gadgets`（from_file）：uniq(&:constraints) → 按约束数升序 → 剔除约束超集
  → 按 offset 排序。**这是输出顺序的权威来源**。
- `refine_gadgets`：score≥0.2 分区 + take_until(3)（level 0）。

### 4b. i386 语义（与 amd64 的差异点）

- `/bin/sh` 是 **GOT 相对**寻址：`lea esi,[ebx-0x565c1]`；
  `rel_sh = DT_PLTGOT − bin_sh 文件偏移`。候选过滤 = 块文本含 rel_sh hex
  （无 posix_spawn 直通、无 jmp_case）。
- 参数在**栈**上：`argument(i) = sp_stack[cur_top + i*4]`，
  `cur_top = esp.evaluate({esp:0})`（esp 须为可求值的直接基）。
- resolve 前置：arg0 含 rel_sh hex → `base_reg = arg0.deref.obj`（**仅基名**，
  不含 imm/deref：`esi-0x565c1` → `esi`；嵌套值 → `[ebp-0x2c]`）；
  unshift `"{base_reg} is the GOT address of libc"` 并删除
  `writable: {base_reg}`。
- `global_var? = str.include?(base_reg)`；`execl` 可解析（`str_sh?` 用
  rel_sh−5 hex），amd64 则直接丢弃。
- `check_argv/check_envp` 的 `Lambda.parse(arg)` **不带 predefined**——
  imm 保持字面值（`esp+0x28` 不得按当前 esp 折叠）。
- xmm 是 4 条 (u32) lane：movq 读写 2 槽、movhps 写 lane 2-3、movaps 写 4 槽；
  `movq xmm, r64` 仅 64 位。
- `xor eax,eax` 不提升寄存器名（i386 ABI 表本身就是 e 名）。

### 4c. build-id 数据库（builds.rs）

- 859 个上游 `.rb` build 离线转换为 `src/builds.db`（编译期 `include_str!`）：
  `@ ver buildid` / `# 注释行`（--info 用）/ `g offset {"e":id,"c":[id..]}`
  / 字符串表（effect+constraint 全局去重，2.0MB → 945KB）。
- 运行时 `OnceLock` 惰性解析；前缀索引（build-id 前 2 hex → 桶）+
  `starts_with` 收敛，多命中报 `Multiple BuildIDs match`（对齐 gem）。
- **gadget 来源优先级**：给 FILE 先查数据库（除非 `-f`）；DB gadgets
  **不经过 trim**（Ruby 里 trim 在 Fetcher#from_file 内部）。

### 4d. --near（near.rs）

- 函数列表（逗号分隔）或 ELF 文件路径（其**带 GLIBC 版本的符号名**集合，
  对齐 `objdump -T | grep -iPo 'GLIBC_.+?\s+\K.*'`——定义与否不限）。
- 函数偏移取 libc 符号表（同名多地址取最小，对齐 objdump -T 首行）。
- 输出：每函数一段，gadgets 按 |offset−func| 升序；`-o json` 输出
  `[{near, near_offset, gadgets}]`。

### 5. 性能设计

- **按需渲染**：全量只解码（~10ms/51 万条）；objdump 行文本只在候选窗口渲染
  （几百行）。比「全量格式化」快 ~7×。
- 零拷贝 ELF（一次性读入）；`symbol_addrs` 预排序 + 二分。
- musl 静态：启动无动态链接开销（对比 Ruby 解释器冷启动 ~300ms）。

实测（Docker arm64，36 libc = amd64 18 + i386 18，-l 1 全量扫描）：

| 工具 | 总耗时 | 单文件 |
|---|---|---|
| one_gadget 1.10.0 (Ruby) | 19600ms | 544ms |
| **rog 0.1 (musl 静态)** | **884ms** | **25ms** |

macOS 原生（M 系列，release）：~18ms/libc；build-id 数据库命中 <1ms。

## CLI

```
rog [FILE | -b BuildID] [-f] [--info ID] [-n FUNCS|FILE] [-s CMD]
    [-l LEVEL] [-r|--raw] [-o pretty|raw|json] [--base N] [--version]
```

`--script` 经 `sh -c "<cmd> <offset>"` 执行（对齐 Ruby 的 `Process.wait(spawn)`）。

## 测试策略

1. **单元测试**（40+）：lambda parse/渲染、emulator 单指令语义（含嵌套 store
   拒绝、xor 提升、movaps 对齐约束、双架构字长/lane）、gadget 评分/trim/合并
   渲染、builds 数据库完整性。
2. **golden 回归**（`tests/golden.rs`）：36 libc（amd64+i386）× 3 level =
   108 组输出与 one_gadget 1.10.0 **逐字节**一致（testdata/ + testdata/golden/，
   以 `-f` 强制扫描语义比对；容器内与 gem 实跑对照亦 108/108）。
3. **CLI 特性测试**（`tests/cli.rs`）：`-b` 前缀/错误/互斥、`--info`、
   `--near` 排序与 ELF 模式、`-f` 语义、`--script`、json。
4. **跨平台验证**：macOS arm64 原生、Linux x86_64 musl（amd64 容器）、
   Linux aarch64 musl（arm64 容器）均过 golden。

## 依赖清单（少而精）

| crate | 用途 |
|---|---|
| goblin | ELF 解析 |
| iced-x86 | x86 解码 + Intel 格式化（no default features，按需开） |
| clap (derive) | CLI |
| serde + serde_json | json 输出 |
| thiserror | 错误处理 |


## 风险与对策

| 风险 | 对策 |
|---|---|
| one_gadget 未来版本语义漂移 | 锁定 1.10.0；golden 集可再生成 |
| iced 与 objdump 文本差异 | IntelFormatter 选项逐项对齐；golden 逐字节断言兜底 |
| 内置数据库过期 | 数据冻结自 1.10.0 发布版（859 条）；`-f` 永远可全量扫描 |
| build-id 前 2 hex 桶倾斜 | 最坏退化线性扫描 859 条（<1ms，无碍） |
