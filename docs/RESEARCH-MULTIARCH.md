# 调研报告：多架构 + musl/uClibc 支持

日期：2026-10-14。参考实现：one_gadget **master 2.1.1**（commit f6e57f0）。
rog 现有 x86 路径对齐的是 1.10.0；新架构按 2.1.1 语义实现。

## 1. 两代框架对比（决定架构策略）

| | 1.10.0（rog 现状） | 2.1.1 master（新架构采用） |
|---|---|---|
| 候选发现 | objdump 文本 `grep -B30` 窗口 + jmp_case | **从 terminal call 反向走 CFG**（CandidateWalk） |
| 模拟器 | 每 arch 独立（x86 共享基类） | Processor 基类 + 4 个架构无关模块 |
| 参数解析 | 混在 fetcher | **ArgumentResolution**（架构无关） |
| 内存模型 | sp 栈表 | **TrackedMemory**（任意基址槽位记忆 + 帧指针） |
| 比较分支 | x86 jcc 后缀表 | **Conditional**（RELATION/COMPARE_OPS 通用） |
| musl | ✗ | ✓（mips-musl fixture 在 spec 里） |
| sectionless ELF | ✗ | ✓（DynamicSymbols，为 OpenWrt musl 做） |
| 窗口反汇编 | 全量 objdump | **scan_calls 字节级 call 定位** + ±0x1000 窗口 |

**决策**：x86 双架构保持 1.10.0 路径不动（108 golden 不破）；新架构
（aarch64/arm/riscv64/mips）走 2.1.1 语义的新管线。两套管线共存，
共享 elf/gadget/builds/near/output 层。

## 2. 各架构语义要点（来自 master 源码）

### 2.1 公共框架（fetchers/base.rb + 4 模块，~1200 行）

- **候选 = 反向控制流走查**：`back_walk(idx)` 从每个 terminal call 行向上：
  fall-through 前驱 + 直接分支前驱（`branch_pred_map` 全量扫描一次构建）；
  条件分支 fork（上限 MAX_FORKS=4），路径长度上限 PATH_BUDGET=80；
  `visited` 集合防环。产出地址递增的行列表（terminal call 在最后）。
- **executed_windows(lines)**：候选的每个后缀 i∈[len-2..0]，切到它到达的
  terminal call；`seen` 去重；`refused_before_call?` 全局拒绝表加速。
- **分支约束**：模拟器 `resolve_pending_branch(cmd)` 用下一行地址 vs 分支
  目标判定 taken/not-taken → 约束（not-taken 时 NEGATE 翻转操作符）。
  可满足性检查 `satisfiable?`（区间交集）→ 不可满足抛 InfeasiblePathError。
- **tautology/contradiction 消除**：`X == X` 剔除、`X != X` 丢弃整个 gadget
  （`comparable_values`：同 obj 的两个 imm 可比较）。
- **safe calls**（SafeCalls::COMMON）：sigprocmask(arg1 nullable_deref)、
  __sigaction(arg1 nullable_deref, arg2 null)、__close(arg0 closed_fd 记录)、
  unsetenv(arg0 global_var?)、posix_spawnattr_setsigmask/setsigdefault
  (arg0 writable, arg1 deref)、posix_spawnattr_*(arg0 writable)。
  caller-saved 寄存器 clobber，返回寄存器置 0。
- **约束收集**（Constraints 模块）：`:writable`/`:readable`（地址型，按键
  去重取最小 offset）、`:raw`、`:cmp`；`drop_implied_nonzero`（地址约束
  蕴含 reg≠0 则删 `<reg> != 0x0`）、`drop_restated_null`；渲染后 sort。
- **deferred reads**：call 的指针参数延迟到模拟结束判定（栈/全局/$base 已
  mapped 则免约束）。

### 2.2 aarch64（fetcher 51 行 + emulator 170 行，最简参考）

- call = `BL imm26`（mask 0xfc000000==0x94000000，字对齐逐字扫描）。
- `adrp dst, imm` → `$base + imm`（libc 相对，模拟器直出 global 形式）。
- ldr/str/stp（pre/post-index 写回）、mov/add/sub/and/orr/eor/bic/lsl/lsr/mvn。
- 分支：`b`/`b.<cond>`（CONDS 表）、`cbz/cbnz`（branch_on_zero）、
  `tbz/tbnz`（branch_on_bit → `(reg & mask) == 0` 形式）。
- 比较：cmp(→sub)/cmn(→add)/tst(→and)；shift 修饰符折叠（`lsl 12` 等，
  asr/ror 不支持则 abort）。
- xzr/wzr=0；w* 是 x* 的 narrow view；x29 帧指针跟踪；argument(i)=x_i。

### 2.3 arm A32/Thumb-2（fetcher 311 行 + emulator 315 行，最复杂）

- **双指令集**：动态符号表 STT_FUNC 的 value 最低位 = Thumb；
  `record_instruction_sets` 构建边界表，`decode_ranges` 按段切换
  `-M force-thumb`；`note_instruction_set` 由后缀 .w/.n 或 2 字节步长推断。
- scan_calls：Thumb BL（半字对 0xf000-0xf7ff + 尾 0xd000 系，offset 位散布
  且 I1/I2 反码）+ A32 BL（cond|101|1，+8 偏移）。
- pc 语义：`$base + addr + (thumb?4:8)`；literal pool：`ldr rX,[pc,#N] @ (addr)`
  注释地址直接读文件字节。
- **GOT base 寄存器 seeding**（PIC）：候选窗口外的 `ldr rB,[pc]; add rB,pc`
  序列回放（SETUP_REACH=400 行回溯）；约束 `rB is the GOT address of libc`
  + 删除对应 writable；窗口自身建立的（window_establishes?）不 seed。
- push/pop reglist（sp 栈表）；blx=bl；`movs/adds/...`（FLAG_SETTING）→ 基础
  助记符；svc=nop。argument(i)=r0..r3，第 5+ 参数 [sp+(i-4)*4]。

### 2.4 riscv64（fetcher 78 行 + emulator 265 行）

- call = `jal`（2 字节对齐逐半字扫描，J 型 imm 位散布 [20|10:1|11|19:12]）。
- `auipc dst, imm` → `pc + (imm<<12)`；配对 `addi` 折出 $base+off。
- 分支即比较：COND 表 16 助记符（beq..bgtz），`record_compare(:sub)` +
  `branch_on_compare` 同指令完成；`j`=无条件；ret/jr/jalr=terminator。
- 内存操作数 `off(reg)` → `[reg±off]`（十进制 offset）；ld/lw/lh/lb（窄于
  size_t → clobbered）、sd/sw/sh/sb（窄 → 写 clobbered 但保留 writable）。
- zero 寄存器=0；s0 帧指针；argument(i)=a_i。

### 2.5 mips o32（fetcher 478 行 + emulator 289 行，GOT 中心）

- **一切经 GOT**：call = `lw t9,off(gp); jalr t9`。fetcher 用 GOT 表
  （DT_MIPS_LOCAL_GOTNO / DT_MIPS_GOTSYM / DT_PLTGOT + gp 偏移 GP_BIAS=0x7ff0）
  把 GOT 槽解析成符号名写回行尾（`jalr t9 <posix_spawn…>`）；全局加载
  `lw aX,off(gp)` 同样注 `# <addr>`（模拟器读作 $base+addr）。
- **延迟槽**：transfer 指令延后一条执行（@delayed）；窗口含 terminal call
  的延迟槽（`emulate(cmds + delay_slot_after)`）；branch_pred_map 边也从
  延迟槽起算；`follows_a_transfer_it_skipped?`（第二行不紧邻首行=跳过了
  所属 transfer 则弃）；`enters_at_an_unset_call?`（首行 jalr 弃）；
  `calls_without_the_callee_in_t9?`（bal/jal 前 t9 未指向目标且目标函数有
  `addu gp,gp,t9` 序言（0x0399e021）则弃）。
- 约束：`gp is the GOT address of libc`（+过 call 后 `[sp+0x18] is the GOT
  address of libc` 形式的恢复槽前提），删除 rooted-at-gp 的 writable/readable。
- 字节序：GOT 读法按 ELF endian（'N*'/'V*'）；两字节序都支持。
- argument(i)：i<4 → a_i；否则 **[sp + i*4]**（o32 槽位含寄存器参数）。

### 2.6 ABI 表（abi.rb）

寄存器名集（objdump 打印名）、NARROW_VIEWS（w0→x0、edi→rdi 等）、
CALLER_SAVED、RETURN_REGISTER、stack_register?（esp ebp rsp rbp sp x29 s0）。

## 3. musl / uClibc 结论

- **musl**：2.1.1 框架直接可用——无版本符号、常 strip 掉 section headers
  （DynamicSymbols + raw disassembly 路径就是为此设计）。execve/execl 是
  musl 导出符号（无 @@GLIBC 版本后缀），terminal_call_regexp 兼容。
  **置信度标注**：musl 结果与 glibc 同管线，标注 `libc: musl`，置信度高。
- **uClibc/uClibc-ng**：无版本符号或简单版本；有 /bin/sh 字符串与 execve。
  同管线预期可用，但无上游参考实现——结果标注 `libc: uclibc` + 需样本
  实测验证；找不到 gadget 属正常（其 do_system 代码布局不同）。
- 实现层面：rog 的 elf.rs 需支持「bin_sh 查找失败时给出明确错误」而非
  假定 glibc；gadget 输出加 `--libc` 提示行（非 glibc 时 confidence 标注）。

## 4. 反汇编器选型（Rust，零 C 依赖约束）

| arch | 方案 | 理由 |
|---|---|---|
| aarch64 + arm(32) | `yaxpeax-arm` crate | 纯 Rust，两个模式都支持，维护活跃 |
| riscv64 | `raki` 或自写 RV64GC 子集解码 | 指令集规整，解码 ~400 行可控 |
| mips o32 | 自写解码器（~500 行） | 无维护良好的纯 Rust MIPS 解码器；o32 常用指令少 |

输出统一为 **GNU objdump 兼容文本行**（`addr:\tmnem\tops ; 注释`），
模拟器按文本行处理——与 Ruby 语义 1:1 对应，golden 对照直接可比。

（最终选型在样本集上实测后定稿；yaxpeax-arm 输出格式需要适配层转成
objdump 文本。）

## 5. 样本集需求映射

| 用途 | 样本 |
|---|---|
| aarch64 glibc golden | 2.23/2.24/2.27/2.43（Ubuntu ports / Debian） |
| arm glibc golden | 2.23/2.27/2.39 |
| riscv64 glibc golden | 2.39（Debian riscv64 port） |
| mips glibc golden | 2.36 mipsel + mips（Debian） |
| musl | Alpine apk / musl.cc 多架构（amd64 i386 aarch64 arm riscv64 mips mipsel × 1.1.24/1.2.x） |
| uClibc-ng | Buildroot 产出 / uclibc.org 下载（1.0.30+ 多架构） |
| IDA MCP 验证 | aarch64 glibc 2.27（有 master spec 期望值可对照） |

## 6. 风险

1. objdump 文本格式对齐（.w/.n 后缀、# 前缀、<> 注释、@ literal pool）——
   逐字段对照 Docker 容器内的 GNU objdump 输出。
2. master 未发布（2.1.1 在 main 分支），语义可能微调——锁定 commit f6e57f0。
3. mips 大端样本获取（Debian 有 mips big-endian port 但已在 archive）。
4. uClibc 样本最难获取——Buildroot 自构建兜底。
