# one_gadget v1.10.0 调研报告

rog 的语义对齐目标锁定 one_gadget **v1.10.0**（2023-06 发布，Ruby 实现）。
本报告记录逆向其完整流水线得到的权威语义——全部结论经 Docker 内 Ruby 探针
实测验证（源码 /tmp/og110，参考输出 /tmp/rog_reference）。

## 1. 总体流水线

```
libc ELF
 → objdump 文本   `objdump --dwarf-start=0 --no-show-raw-insn -w -d -M intel`
 → fetcher#candidates   grep -E 'call.*<(exec[^+]*|posix_spawn[^+]*)>$' -B 30 分块
                         + loop-shift 切块 + slice_prefix + amd64 文本过滤
 → fetcher#jmp_case     grep -E '# <bin_sh_hex>' -A 8 分块 → jmp 截断 → 目标缝合
 → fetcher#find         每候选×每后缀 emulate（文本模拟器）→ resolve → Gadget
 → from_file            trim_gadgets（uniq/子集剔除/排序）
 → CLI                  refine_gadgets（level 过滤）→ inspect 渲染
```

关键认知：**1.10.0 没有真正的 CFG/二进制分析**——所有判定都基于 objdump
文本行（grep 分块、子串匹配、文本 parse）。逐字节兼容的正确路径是复现这套
文本语义，而非"更聪明"的算法。

## 2. objdump 文本层

- 命令 `objdump --dwarf-start=0 --no-show-raw-insn -w -d -M intel`：
  **无字节列**（--no-show-raw-insn）、不自动换行（-w）→ 每指令恰好一行。
- Intel 风格细节：hex 带 `0x` 前缀、rip 相对注释 `# <target> <sym>`、
  内存操作数显式尺寸前缀（QWORD PTR 等）。
- 符号注释：带 symbol versioning 的动态符号显示 `name@@VER`（default）
  或 `name@VER`；**同地址双 weak 别名（sigaction/__sigaction）时 BFD 显示
  `__` 前缀者**——这直接影响 call 注释 → 候选过滤（2.23 曾因此丢全部 gadget）。

## 3. 候选发现（base.rb + amd64.rb）

### candidates（基本块）

1. `grep -E 'call.*<(exec[^+]*|posix_spawn[^+]*)>$' -B 30`：
   匹配行 = 终结 call（注释符号以 exec/posix_spawn 开头、无 `+` 偏移）。
2. grep `-B30` 的 `--` 分块语义：块下界 = 上一匹配行 +1（不是简单 -30）。
3. 块内 loop-shift：首个匹配 call 切块，剩余继续 → 连续 call 逐块产出。
4. `slice_prefix`：rindex 找**最后**一个分支行（**整行**子串匹配
   jmp/je/jne/jl/jb/ja/jg——注释文本也算），裁掉它及之前。
5. amd64 过滤（**最后**做，基于整块 join 文本）：
   - 含字面 `posix_spawn@` → 直通（注意：区分 posix_spawnattr_init 等）
   - 否则须 `include?(bin_sh_hex)` 且**最后一行**含 `execve`

### jmp_case

1. `grep -E '# <bin_sh_hex>' -A 8`：rip 相对目标恰为 /bin/sh 偏移的行。
2. **-A8 分块合并**：相邻匹配 ≤8 行时 `--` 合并为一块（2.26 多出 3 个假
   gadget 的根因：合并后 call-before-jmp 拒绝语义作用于整块）。
3. 块内首个含 'jmp' 的行截断候选；截断前含 'call' → **整块丢弃**。
4. jmp 目标处 `objdump --start-address` 反汇编 100 字节，到首个行含
   `execve` 的 call；候选 = 前段 + 目标段缝合。

## 4. 模拟器（x86.rb，13 条指令）

- 指令集：add/call/jmp/lea/mov/nop/push/sub/xor/movq/movaps/movhps/punpcklqdq。
  **其余指令遇即 refused**（没有 jcc/cmp/test/endbr——遇 cmp 即停，
  这就是为什么候选必须 slice_prefix 干净）。
- 匹配基于**文本**：`match?` 是非锚定 `/inst\s/`；`fetch_args` 在最后一个
  `#` 截断、括号深度感知逗号分割、gsub 剥尺寸前缀。
- 寄存器 = Lambda 或 Integer；**窄名/全名相互独立**（eax ≠ rax），
  例外：`xor edx,edx` 的 e 前缀提升写 rdx=0；r12d 不在 ABI 表 → raise。
- 内存：只跟踪 sp/bp 两张栈表（`get_corresponding_stack` 按渲染文本
  含 rsp/esp 或 rbp/ebp 子串判定）；store 先记 `writable:` 约束
  （rip 基豁免），`deref_count != 1` 或 `evaluate` raise（**嵌套 obj**）
  则停止；load **无读回**（永远得到地址 lambda 本身）。
- `lea reg,[mem]`：parse 整体（predefined 折叠）再 `.ref!` 剥一层。
- 安全调用表（不 clobber）：sigprocmask、__close、unsetenv（arg0 须全局）、
  `__sigaction`（arg1 全局且 arg2==0）。其余 call 拒绝。
- Lambda.parse 的 predefined 折叠：mem_obj 基名查 predefined → 有则替换；
  `obj += imm` 在 deref==0 时直接折叠 imm，deref>0 时**套新层**
  （obj=Nested(旧整体)，deref 归零）——`[[rsp+0x38]+0x4]` 由此而来。
- Const(0) 渲染为十进制 "0"（Ruby Integer#to_s）——argv 判定依赖。

## 5. resolve 与约束（base.rb）

- execve：arg0 须含 `rip+0x`（bin_sh 位置，否则丢弃）；argv 三路
  （栈上已知有效 / 全局含 sh 生成 `{"sh","-c",...}` / 需构造——构造时
  **仅 i==1 的全局变量**渲染 `"-c"`）；envp（`[[全局]]` → environ 免约束、
  `[[非全局]]` → 丢弃、栈 → `{...} is a valid envp`）。
- posix_spawn：args[1]/[4]/[5] 走 execve 检查（allow_null_argv=false）；
  pid 栈判定免约束；file_actions `(s32)[x+4] <= 0`；attrp `(u16)[x] == NULL`。
- execl 在 amd64 直接 NotImplementedError → 丢弃。
- `constraints` 输出：writable 按 deref==0 归并基名去重，整体字典序排序。

## 6. trim 与输出顺序（fetcher.rb from_file）

**输出顺序的权威来源**（不是 find 顺序）：

1. `uniq(&:constraints)`——约束列表完全相同只留首个；
2. `sort_by { constraints.size }`（稳定）；
3. 剔除约束超集：gadget i 若被任何更前面（约束更少）的 j 满足
   `constraints[j] ⊆ constraints[i]` → 丢弃 i；
4. `sort_by(&:offset)`。

level 过滤：score≥0.2 分区（空则取低分区）+ take_until(pool, 3)
（按第三高 score 阈值全保留）。score = 各约束 calculate_score 连乘
（`||` 取 max；`& 0xf` 0.95；GOT 0.9；writable 栈 0.95/其他 0.81；
NULL 类按 parse 形状 0.9^(deref+extra)；valid argv/envp 0.2）。

## 7. 输出格式

- `inspect`：`{offset} {effect}\n` + 空行约束块（writable 合并为
  `address(es) ... is/are writable`）+ 末尾 `\n`。
- CLI `display_gadgets`：`map(&:inspect).join("\n")` → **gadget 间空行**。

## 7b. i386 语义（fetchers/i386.rb + emulators/i386.rb，探针验证）

| 语义 | one_gadget 1.10.0 | rog |
|---|---|---|
| /bin/sh 定位 | GOT 相对：`lea esi,[ebx-0x565c1]`；rel_sh = DT_PLTGOT − 文件偏移 | `elf.rs rel_sh()`（goblin 动态段 DT_PLTGOT） |
| 候选过滤 | 块文本含 rel_sh hex（无 posix_spawn 直通/jmp_case） | `search.rs` X86 分支 |
| 传参 | 栈：`sp_stack[esp.evaluate + i*4]` | `Emulator::argument` X86 分支 |
| GOT 基 | `arg0.deref.obj.to_s`（**仅基名**，不含 imm/deref） | `Lambda::obj_str()` |
| 全局变量 | `str.include?(base_reg)` | resolver `Ctx` |
| execl | 可解析（str_sh? = rel_sh−5 hex） | `resolve_execl` |
| call 目标 | objdump rel32 call | iced `NearBranch32`（首次实现漏掉 → call_idxs 空） |
| argv/envp | `Lambda.parse(arg)` **不带 predefined** | 空 predefined 表解析 |

**实现期踩坑记录**（对拍 Docker 探针定位）：
1. `direct_call_target` 只认 `NearBranch64` → i386 rel32 call 全漏（候选=0）。
2. `inst_push` 要求 bare sp，但 `sub esp,0x4` 后 esp 已带 imm——Ruby
   `registers[sp] -= size_t` 对带 imm 的 lambda 同样有效。
3. argv 偏移被 predefined 折叠（esp+0x28 → esp+0x1c）：Ruby 在 check_argv
   里重新 parse 字符串、不带寄存器上下文。
4. `movaps` 写满固定 4 lane 导致 amd64 输出多 2 个伪造槽：Ruby lane 数 =
   `128/bits`（amd64=2），xmm 值改为按架构定长的 `Vec`。

## 7c. build-id 数据库（gadget.rb ClassMethods）

- 859 个 `builds/libc-<ver>-<sha1>.rb`：头部注释（来源 URL/版本说明）+
  `Gadget.add(build_id, offset, constraints:, effect:)` 行。
- CLI：`-b ID`（唯一前缀，多命中报 Candidates 列表）；`--info ID` 打注释；
  给 FILE 先查数据库除非 `-f`（force_file）。
- **DB gadgets 不 trim**：trim 在 `Fetcher#from_file` 内部，`builds()` 直接返回。
- rog 落地：离线转 `src/builds.db`（字符串表去重 2.0MB→945KB），编译期内嵌，
  `OnceLock` 惰性解析，2-hex 前缀桶索引。
- `--near`：`handle_near` 函数偏移用 `objdump -T`（rog 用符号表等价实现）；
  GOT 函数集 = 目标 ELF 带 GLIBC 版本符号（定义与否不限——grep 语义）。
- `--script`：`Process.wait(spawn("cmd offset"))` → `sh -c`。

## 8. rog 的等价性映射

| Ruby 文本操作 | rog 实现 | 等价性依据 |
|---|---|---|
| objdump 全量文本 | iced-x86 解码 + 按需渲染（IntelFormatter 逐项对齐选项） | golden 逐字节 |
| grep 终结 call 正则 | call/jmp 目标元数据 + nearest_symbol 注释判定 | 符号名不含 `<>#+` 特殊交互 |
| `# <hex>` 针 | `rip_target == bin_sh` | 更长同前缀 hex 超出 vaddr 空间 |
| `-B30/-A8` 分块 | 显式复现 `--` 分块/合并语义 | 逐块边界对拍 |
| 文本模拟 | 同 13 指令文本模拟器（操作数文本 parse） | 单指令单测 + golden |
| evaluate raise | `eval_offset` 只接受直接 sp/bp 基 | Docker 探针验证（2.27 e5551） |

## 9. 性能分析（为什么 one_gadget 慢）

| 阶段 | one_gadget | rog |
|---|---|---|
| 启动 | Ruby 解释器 ~300ms | 静态 musl 二进制 <1ms |
| 反汇编 | objdump 子进程全量文本（~200ms） | 进程内解码 ~10ms，文本按需 |
| 候选/模拟 | grep 子进程 ×2 + Ruby 字符串处理 | 元数据扫描 + 文本模拟 ~4ms |

实测（同容器、36 libc=amd64 18 + i386 18、-l 1 扫描）：19600ms vs 884ms → **22.2×**。

## 10. 验证方法

- 参考输出：Docker（arm64 Ubuntu + ruby one_gadget 1.10.0）对 36 个
  glibc-all-in-one libc（amd64 + i386）生成 `-l 0/1/2` 输出 → `testdata/golden/`。
- Ruby 探针：容器内直接调 `Fetcher#candidates/emulate/resolve` 定位
  语义分歧（jmp_case 块合并、嵌套 evaluate 等结论都来自探针）。
- 逐字节 diff 进 cargo test（`tests/golden.rs`，8 线程并行 ~2s）。
