# 设计：可扩展架构抽象（多架构 + musl/uClibc）

依据 docs/RESEARCH-MULTIARCH.md 的调研结论。核心决策：

- **x86（amd64/i386）保持 1.10.0 管线不动**（108 golden 逐字节锁定）。
- **新架构（aarch64/arm/riscv64/mips）走 2.1.1 管线**：反向 CFG 走查 +
  通用 Processor（Conditional/Constraints/TrackedMemory/DataProcessing/SafeCalls）
  + ArgumentResolution。
- 两管线共享：elf 解析、gadget 表示、builds DB、near、输出层。

## 1. 模块布局

```
src/
  elf.rs            # +Arch::{AArch64,Arm,Riscv64,Mips{,El}}；libc 类型探测(glibc/musl/uclibc)
  arch/
    mod.rs          # trait ArchDef：架构定义点的唯一接口
    aarch64.rs      # 寄存器表/ABI/scan_calls/分支分类/objdump 文本规范化
    arm.rs          # + 双指令集边界/GOT seeding/literal pool
    riscv64.rs
    mips.rs         # + GOT 表解析/延迟槽
  lambda.rs         # +Operation(op,rhs)（(a & b) 形式）、$base
  emulator/
    mod.rs          # Processor 基类：生命周期/安全调用/clobber/约束收集
    conditional.rs  # 比较与分支约束（RELATION/COMPARE_OPS/satisfiable）
    memory.rs       # TrackedMemory：任意基址槽位 + 帧指针 + derived_writes
    x86.rs          # 现有 x86 模拟器（1.10.0 语义，保持）
    aarch64.rs arm.rs riscv64.rs mips.rs
  search.rs         # x86: grep-B30 语义（不动）；新: candidate_walk.rs
  candidate_walk.rs # 反向 CFG：predecessors/branch_pred_map/back_walk/forks
  resolve.rs        # ArgumentResolution（架构无关，从 resolver.rs 泛化）
  textgen/          # 反汇编文本生成（objdump 兼容行）——各解码器 → 统一文本
    mod.rs aarch64.rs arm.rs riscv64.rs mips.rs
```

## 2. 关键 trait

```rust
pub trait ArchDef {
    fn name(&self) -> &'static str;
    fn bits(&self) -> u32;                       // 32/64
    fn registers(&self) -> &'static [&'static str];
    fn sp(&self) -> &'static str;                // "sp"
    fn pc(&self) -> &'static str;
    fn frame_reg(&self) -> Option<&'static str>; // x29/s0/None
    fn argument(&self, idx: usize, regs: &RegFile, stack: &TrackedMem) -> Val;
    // 反汇编文本行（objdump 兼容）→ 结构化判定
    fn branch_kind(&self, line: &Line) -> Option<BranchKind>; // cond/uncond/terminator
    fn call_target(&self, line: &Line) -> Option<u64>;
    fn scan_calls(&self, base: u64, data: &[u8], targets: &HashSet<u64>) -> Option<Vec<u64>>;
}
```

模拟器统一处理「文本行」，与 Ruby 语义一一对应；每个新架构 =
ArchDef（元数据+分类）+ emulator handlers（指令语义）+ textgen（解码→文本）。

## 3. 反汇编器选型（冻结）

- aarch64/arm32：**yaxpeax-arm**（纯 Rust）→ 文本适配层。
- riscv64：自写 RV64 解码子集（~400 行，仅 gadget 路径指令）。
- mips o32：自写解码（~350 行）。两字节序共用逻辑（u32 字序翻转）。

文本格式严格对齐 GNU objdump（golden 对照的前提）：
`<addr>:\t<mnemonic>\t<operands>\t; <comment>`，各架构的注释规则
（`# imm`、`@ (addr)`、`// alias`）在 textgen 内逐一对齐。

## 4. musl / uClibc 策略

- elf.rs 探测：`.dynstr` 无 `GLIBC_` 版本符号 + 存在 `musl` banner 字符串
  （`__libc_version`/build id 区域）→ musl；`uClibc` 字符串 → uclibc。
  探测结果只影响**输出标注**与 confidence，不影响管线。
- Gadget 输出：非 glibc 时在 pretty/json 增加 `libc: <type>` 字段；
  CLI 头行提示 `[OneGadget] libc appears to be musl 1.2.5 (confidence: high)`。
- uClibc 无上游参考 → 约束标注 `heuristic`；musl 经 one_gadget 2.1.1
  fixture 验证 → `verified`。

## 5. 测试策略

1. golden：one_gadget master fixtures 的 spec 期望值（aarch64 4 个版本、
   arm 3、riscv64 1、mips 3 = 11 个 libc 的 offset 列表 + 抽样 constraint 文本）
   → tests/golden_arch.rs。
2. 样本集 e2e（ROG_LIBC_SAMPLES_DIR）：每 (arch × libc) ≥1 个样本
   `rog <file> -l 1` 不 panic、输出可解析、非空（uclibc 允许空但须标注）。
3. Docker 对照：容器内跑 Ruby one_gadget master（已克隆 /tmp/og-master）
   与 rog 逐字节比对（样本集全量）。
4. 单元：conditional satisfiable、tracked_memory 回读、mips GOT 解析、
   arm thumb 判定、各 textgen 与 objdump 快照对照。
