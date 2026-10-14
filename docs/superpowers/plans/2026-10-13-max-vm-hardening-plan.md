# xollvm max VM Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` for inline execution, or `subagent-driven-development` only if the user chooses delegation. Execute task-by-task; do not implement before this plan is reviewed.

**Goal:** 为 xollvm max 提供 96-opcode ISA、最终 ELF 编码目标、白盒 AES、完整 CALL 多态和加固的独立嵌套引擎。

**Architecture:** 先统一引擎解码与 CALL 上下文，再扩展共享的 ISA/layout 描述。白盒替换 VM 的 key-reconstruction 接口；最终地址封装由 compiler descriptor、hardener 和正式链接包装器共同完成。最后启用 max 新配置，并验证所有组合和实际开销。

**Tech Stack:** C++20、LLVM 23、LLVM Object、AArch64 Android ELF64 little-endian PIE、Clang/LLD、Python pytest、现有 C++ gtest。

**Spec:** `docs/superpowers/specs/2026-10-13-max-vm-hardening-design.md`

## Global Constraints

- 新增重型保护集中进入 `preset=max`；用户接受明显的体积、编译时间和运行开销增加，无硬性倍率预算。
- 新 ISA：原 56 个逻辑 opcode 加 40 个真实 opcode，`OP_COUNT=0x60`，ISA version 2；新增发射路径由 `extendedISA` 控制。
- 新地址编码必须检查最终 ELF；未后处理的 encodedTargets 入口 fail closed，不能静默退回明文表。
- 白盒必须融合 key 和内部编码，不生成用于重建 176-byte expanded key 的配对材料。
- 保留 preset 展开后显式参数覆盖的语义；不自动开启 root 检测或网络依赖。
- 层级最大为 2；inner 的 nestedVM 必须为 false。内层监控不新增线程。
- 变更只在 xollvm；demo 不是本阶段实现对象，测试不使用真实凭据。
- 保留当前 4 个未提交源码/测试改动；不自动提交、推送、初始化仓库或删除旧文件。每阶段记录可提交的精确文件范围，只有用户要求时提交。
- 构建使用 Termux 用户；Android 测试 C++ 可执行文件使用 `-static-libstdc++`。
- C++ K&R 风格，关键注释用中文。每次修复失败最多 3 次，达到上限汇报并停止猜测。
- 测试基线为 290 Python / 62 C++，不得用 skip 或放宽断言掩盖回归。

## Review Focus

1. 不同源文件链接在同一 PIE 后，目标重定位不能在启动时恢复明文槽；Task 8 覆盖 RELA、Android packed RELA、RELR 和链接 GC。
2. 同一 engine 先后加入不同 CALL 类型时，所有变体必须读取自己的完整解码上下文；Task 2 覆盖新增类型、StrongBC、lazy 及加密寄存器。
3. lazy 解码在同块/跨块/倒序 IP 和递归并发下不能污染其他调用缓存；Task 10 验证实际 keystream 调用次数和隔离。
4. 融合遇到别名、volatile/atomic、不同基本块、非唯一使用和 poison-sensitive 运算时不能改变定义良好的行为；Tasks 4–6 覆盖不融合及差分。
5. 显式关闭新配置、未知目标平台、损坏/重复封装输入时不得悄悄改变保护承诺；Tasks 8、9、12 覆盖拒绝与 effective-config 诊断。

## 文件责任和依赖

| 文件 | 责任 |
| --- | --- |
| `VMPass_Decode.cpp`、`VMPass_Decode.h` | 统一 byte load、salt、lazy/白盒解码；不读取临时 VMImpl 的其他实例成员 |
| `VMPass_Layout.cpp`、`VMPass_Layout.h` | ISA v2 指令字段宽度、布局、长度和边界验证 |
| `VMPass_SuperOps.cpp` | 新融合匹配和记录，保持 emitter 主流程清晰 |
| `VMPass_Targets.cpp`、`VMTargetEncoding.h` | 待封装 descriptor、目标加载、统一可逆编码定义 |
| `tools/xollvm-elf-hardener/VMTargets.cpp`、`VMTargets.h` | 最终 ELF 目标封装与结构校验 |
| `VMWhiteBoxAES.cpp`、`VMWhiteBoxAES.h` | 编译期密钥融合/内部编码生成和参考求值 |
| `VMPass_WhiteBox.cpp` | 向目标模块生成只读白盒表与轮执行函数 |
| `tools/xollvm-link` | 安装的 link→targets→audit→seal→verify→promote 包装入口 |
| 现有 `VMPass_*.cpp` 和头文件 | 接入上述单一职责模块，不全面重写 |
| `utils/vm_hardening_support.py` | 无凭据 IR/原生 fixture 构建与运行公共工具 |
| `utils/test_vm_*.py`、`utils/VMRequirementsTest.cpp` | 功能、ELF 结构和负例验证 |
| `utils/deobf_bench` | AArch64 成品攻击和成本测量，区分失败种类 |

所有新的 compiler `.cpp` 加入现有 `OBF_SOURCES`；target hardener 的 `.cpp` 加入它自身 CMake target。白盒生成不依赖新第三方库。

## 标准命令

以下命令的工作目录分别指定为仓库 `xollvm` 或正式 `build-sensitive`；不要把环境切到旧 build。

```bash
# workdir=/data/user/0/com.termux/files/home/xollvm-android/build-sensitive
cmake --build . --parallel 5 --target opt clang xollvm-elf-hardener VMRequirementsTests
./tools/Obfuscator/VMRequirementsTests --gtest_brief=1

# workdir=/data/user/0/com.termux/files/home/xollvm-android/xollvm
XOLLVM_OPT=/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/bin/opt XOLLVM_TEST_CLANG=/data/user/0/com.termux/files/home/android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64/bin/clang PYTHONDONTWRITEBYTECODE=1 python -m pytest utils -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-vm-final
git diff --check
```

阶段 tests 用各 Task 的明确命令；重型性能/攻击样本不用混进常规 pytest。所有 timeout 都报告阶段与 stderr，不把 timeout 当抗性通过。

---

### Task 1：统一 byte 解码并建立无凭据测试入口

**Files:** 新建 `include/llvm/Transforms/Obfuscator/VMPass_Decode.h`、`VMPass_Decode.cpp`、`utils/vm_hardening_support.py`、`utils/test_vm_decode_context.py`；修改 `VMPass_Impl.h`、`CMakeLists.txt`。

**Interfaces:** `VMByteDecodeContext` 持有 BC/salt/lazyctx/keystream FunctionCallee、EncBytecode/StrongBC/LazyDecrypt、lazy layout offsets。`emitVMByteLoad(IRBuilder<>&, const VMByteDecodeContext&, Value* Index, const Twine&) -> Value*`；VMImpl 的 loadBC/loadBCDyn 都调用它。

- [ ] 写参数化 C++/IR fixture，覆盖两个不同 context 的 byte load、固定/动态 offset、StrongBC on/off 和 lazy on/off。测试 fixture 的 Python 接口为：

```python
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

@dataclass
class VMTools:
    opt: Path
    clang: Path
    clangxx: Path
    sysroot: Path
    hardener: Path

def tools() -> VMTools:
    root = Path(__file__).resolve().parents[2]
    build = root / 'build-sensitive/bin'
    ndk = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    result = VMTools(Path(os.environ.get('XOLLVM_OPT', build / 'opt')),
                     ndk / 'bin/clang', ndk / 'bin/clang++', ndk / 'sysroot',
                     build / 'xollvm-elf-hardener')
    for path in (result.opt, result.clang, result.clangxx, result.hardener):
        if not path.is_file():
            raise RuntimeError(f'required tool missing: {path}')
    return result

def checked(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, result.stdout + result.stderr
    return result

def transform(work: Path, source: str, seed: int = 42,
              extra: tuple[str, ...] = ()) -> Path:
    src, out = work / 'input.ll', work / 'obf.ll'
    src.write_text(source)
    checked([str(tools().opt), '-passes=obfuscation', '-obf-verify',
             f'-obf-seed={seed}', *extra, '-S', str(src), '-o', str(out)])
    return out

def build_native(work: Path, ir: Path, harness: str,
                 finalize_targets: bool = False) -> Path:
    t = tools()
    lowered, src, obj, exe = (work / name for name in
                              ('lowered.ll','harness.cpp','vm.o','native'))
    lowered.write_text('\n'.join(line for line in ir.read_text().splitlines()
                                if not line.startswith('@llvm.global.annotations')) + '\n')
    src.write_text(harness)
    checked([str(t.clang), '--target=aarch64-linux-android26', '-O0',
             '-c', str(lowered), '-o', str(obj)])
    checked([str(t.clangxx), '--target=aarch64-linux-android26',
             f'--sysroot={t.sysroot}', '-std=c++20', '-static-libstdc++',
             '-Wl,--rosegment', str(src), str(obj), '-ldl', '-pthread', '-o', str(exe)])
    if finalize_targets:
        checked([str(t.hardener), 'targets', '--input', str(exe), '--output', str(exe)])
    return exe

def run_case(exe: Path, args: tuple[str, ...], expected: str) -> None:
    result = checked([str(exe), *args], timeout=30)
    assert result.stdout == expected
```

实现 helper 时：transform 使用 `-passes=obfuscation -obf-verify -S`；build_native 只去 frontend annotations，不去 obfuscation metadata，使用 Android26 和 static libc++；run_case 使用 30 秒 timeout 并断言退出码/完整输出。不要在 production 添加测试专用入口。

- [ ] 红测命令：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_decode_context.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-decode-red`。预期新增 context/API 测试失败。
- [ ] 抽出 loadBC/loadBCDyn 的公共逻辑，含现有 ksByteIR 和 lazy AES 调用。相同上下文输出应与旧路径语义一致；先不更改 lazy 缓存策略。
- [ ] 同一命令改 basetemp 为 `max-decode-green` 验证；再执行现有 `utils/test_vm_pipeline_lifecycle.py` 和 62 项 C++ 基线。
- [ ] 审阅捕获 Value 的函数归属和 dominance，记录 Task 1 diff，未经请求不提交。

### Task 2：CALL 全变体、增量类型和正确 ABI

**Files:** 修改 `VMPass_Impl.h`、`VMPass_Handlers.cpp`、`VMPass_Dispatch.cpp`；新建 `utils/test_vm_call_variants.py`；扩展 `VMRequirementsTest.cpp`。

**Consumes:** Task 1 的 VMByteDecodeContext / emitVMByteLoad。

**Produces:** `SmallVector<CallSwitchInfo, 4> CallSW[5]`；每个 CallSwitchInfo 带 Variant、Decode、各寄存器/密钥上下文、参数起点、返回转换信息。`extendVMCallSwitch(CallSwitchInfo&, FunctionType*, unsigned TypeIndex)` 初始和后续类型共用。

- [ ] 先添加如下真实 native witness，循环调用以覆盖全部 IP/salt 变体选择；另用两个函数按相反顺序注册类型。

```cpp
extern "C" int add2(int a, int b) { return a + b; }
extern "C" uint64_t mix3(uint64_t a, uint64_t b, uint64_t c) { return (a ^ b) + c; }
extern "C" void store1(int* p, int a) { *p = a; }
extern "C" int* identity(int* p) { return p; }
extern "C" double sumfp(float a, double b) { return double(a) + b; }
// 被保护函数分别调用上述声明；测试预期 add2(9,-4)=5、mix3(9,4,3)=16、sumfp(1.5f,2.25)=3.75。
```

各 witness 注解使用 `vm(handlerVariants=4,strongBytecode=1,encBytecode=1,lazyDecrypt=1,hardened=1)`；C++ 测试再检查每个 CALL switch 具有所有需求类型，表槽不全部相同。调用 16 个参数的定义良好 fixture，不支持 ABI 的负例必须明确失败。

- [ ] 红测：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_call_variants.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-call-red`；预期当前 StrongBC fatal 或不完整 CALL 变体失败。
- [ ] 将单个 CallSW 改集合，buildCall2 追加每个变体上下文；增量扩展遍历所有项。通过 Task 1 decoder 重读参数，修正 ArgByteBase 的实际字节偏移，以 emitter 编码为依据，不保留现有未验证的 `+2` 假设。
- [ ] 使用源函数精确参数/返回类型与 calling convention，保留窄整数扩展和 vararg promotion 规则；支持范围之外明确拒绝，不能沿用 ptr 伪装整数的 ABI 猜测。
- [ ] 去除 CALL table last-variant pinning；重建工具，绿测以上用例和 C++ 全量；记录 diff。

### Task 3：ISA v2 的共享字段描述与随机布局

**Files:** 新建 `VMPass_Layout.h`、`VMPass_Layout.cpp`；修改 `VMPass_ISA.h`、`VMPass_Emitter.h/.cpp`、`VMPass_Verifier.cpp`、`VMPass_Handlers.cpp`、`VMPass_Requirements.cpp`、`ObfuscationConfig.h`、`VMPass.cpp`；新建 `utils/test_vm_operand_layout.py`。

**Interfaces:** `VMFieldRole {Dst,SrcA,SrcB,SrcC,Predicate,Kind,Immediate,Pointer,Index,Scale,Target}`；`VMInstructionLayout::offset(VMOp, VMFieldRole) const -> unsigned`、`size(VMOp) const -> unsigned`。立即数字段连续且 little-endian。跳转表和 CALL 变长尾部由专门 schema 处理，不假装固定长度。

- [ ] C++ fixture 使用相同字段集以不同顺序编码，verifier 接受合法排列、拒绝重复角色/重叠字段/越界字段。native fixture 在 seeds 1、42、20260930 下输出一致。

```cpp
TEST(VMOperandLayout, KeepsWidthsAndChangesOffsets) {
    auto A = VMInstructionLayout::forSeed(1);
    auto B = VMInstructionLayout::forSeed(42);
    EXPECT_EQ(A.size(OP_BINOP), B.size(OP_BINOP));
    EXPECT_NE(A.fingerprint(), B.fingerprint());
    EXPECT_TRUE(A.validate());
    EXPECT_TRUE(B.validate());
}
```

- [ ] 红测：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_operand_layout.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-layout-red`。
- [ ] 搬迁固定 offset 的公共定义到 schema，emitter、size pass、verifier、handler 从同一 schema 取值。operandLayout=false 为原顺序。将 Cast64 的逻辑范围判断换成明确的编码 case 分类，补 FCast 和 Select permutation。
- [ ] ISA version=2 纳入 engine key；对新增布局造成的 decoder 不一致立即 fail，禁止 verifier 用错误 layout。
- [ ] 重建，绿测和现有需求/bytecode verifier tests；检查无需 layout 的指令仍保持合法。

### Task 4：18 个 i32/i64 立即数 opcode

**Files:** 修改 `VMPass_ISA.h`、`VMPass_Emitter.cpp`、`VMPass_Handlers.cpp`、`VMPass_Verifier.cpp`、`VMPass_Requirements.cpp`、Task 3 layout；新建 `utils/test_vm_extended_isa.py`。

**Produces:** ADDI/SUBI/MULI/ANDI/ORI/XORI/SHLI/LSHRI/ASHRI 的 32/64 位形式，各带 Dst、SrcA、Immediate；新增 domain 为 `0x38..0x49`。

- [ ] 参数化真实 IR tests：每个 opcode 有 native witness，立即数 0、1、最大值、符号位；非交换操作立即数在左时不误选右立即数 opcode。位移范围仅取 `[0,width)`。

```python
@pytest.mark.parametrize('width,opcode', [(w, op) for w in (32,64)
    for op in ('add','sub','mul','and','or','xor','shl','lshr','ashr')])
def test_immediate_semantics(width, opcode, tmp_path):
    # fixture 在相同进程调用原函数和 VM 函数，比对边界与固定 seed 的伪随机输入。
    ir = immediate_fixture(width, opcode, literal=3)
    exe = build_native(tmp_path, transform(tmp_path, ir), immediate_harness(width))
    run_case(exe, (), 'equal\n')
```

immediate_fixture/immediate_harness 在本测试文件定义，harness 不从 emitter 计算预期，调用独立 native 基线；再用 C++ emitter test 断言选择了目标逻辑 opcode。

- [ ] 红测：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_extended_isa.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-immediate-red`。
- [ ] 配置 extendedISA=false/true，增加发射和 verifier 分支；不改变 defined overflow wrapping；不可删除 poison 语义约束。需求收集按真实 opcode 裁剪。
- [ ] 重建绿测；加入截断 immediate、错误寄存器文件、非法 opcode 负例。

### Task 5：16 个计算复合 opcode

**Files:** 新建 `VMPass_SuperOps.cpp`；修改 Emitter 的融合记录/size/emit、Handlers、Verifier、Layout、Requirements 和 CMake；扩展 `utils/test_vm_extended_isa.py`。

**Produces:** `0x4a..0x59`：MULADD64、SHLADD64、CMPSEL64、ANDCMPZ64 和每宽度 XORADD/ANDADD/ORADD/ADDXOR/SUBXOR/MULXOR。融合记录由 `VMFusion {Consumer, Producer, Opcode, Operands}` 表示，在唯一扫描中构建，size/emit 只消费同一记录。

- [ ] 每 opcode 一份 IR 与 native 基线；使用 `uint32_t/uint64_t` 确保基线 overflow 已定义。CMPSEL64 的 compare 输入/selected 输出是 i64，谓词结果不误存到 i64 bool 文件。

```cpp
uint64_t baseline_xoradd(uint64_t a, uint64_t b, uint64_t c) { return (a ^ b) + c; }
uint32_t baseline_subxor(uint32_t a, uint32_t b, uint32_t c) { return (a - b) ^ c; }
```

- [ ] 红测同 Task 4 命令，basetemp=`max-super-red`；增加不同 BB/两个 live uses/中间调用/融合冲突的回退用例。
- [ ] 按消费者位置发射，同 BB 且无副作用跨越才融合；确保 Producer 所有被删除 uses 合法，避免双重融合。
- [ ] 新 opcode length/field schema 与 branch IP 一致；重建绿测，运行原有 4 个 superOps 用例。

### Task 6：6 个 GEP 访存融合并完成 96-opcode 域

**Files:** 修改 Task 5 matcher、Emitter、Handlers、Layout、Verifier、Requirements、ISA；扩展 `utils/test_vm_extended_isa.py`。

**Produces:** `0x5a..0x5f`：GEP_LOAD8/16/32/64 和 GEP_STORE32/64；OP_COUNT=0x60，decoy base=OP_COUNT，不硬编码旧 0x38。

- [ ] 建立负 index、正 index、unaligned 合法 load、相同地址先写后读的 native fixture。volatile/atomic、多级不支持 GEP、跨 BB 和多 uses 保留原路径。

```cpp
uint32_t baseline_load(const uint32_t* base, int64_t idx) { return base[idx]; }
void baseline_store(uint64_t* base, int64_t idx, uint64_t value) { base[idx] = value; }
```

- [ ] 红测 Task 4 命令 basetemp=`max-memory-red`；C++ 断言 `OP_COUNT==96`、40 个新增 opcode 每个有 emitter witness，全部 decoy slot 互不冲突。
- [ ] 融合保持 scale、pointer arithmetic、width、alignment；不把有符号 index 变成 unsigned。新增 handler 不承担原 unsupported 类型的隐式降级。
- [ ] 完成 verifier、需求报告名称、所有由 OP_COUNT 决定的 bounds 更新；绿测整个 ISA suite 和 C++ 全量。

### Task 7：目标地址编码的 AArch64 探针与格式

**Files:** 新建 `VMTargetEncoding.h`、`VMPass_Targets.cpp`、`utils/test_vm_target_encoding.py`；修改配置、engine key 和 CMake。

**Interfaces:** target descriptor version=1；包含 role、slot count、anchor 引用、table 引用、处理状态和按槽编码参数。文件字段用固定宽度 little-endian，不依赖 C++ struct packing。

明确编码算法：对目标与槽地址的 unsigned 64-bit 差值 `D`，`E=rotl64((D xor K)+A,R)`，解码 `D=(rotr64(E,R)-A) xor K`，`P=slotAddress+D`；R 在 1..63。K/A/R 按 role/slot/seed 派生，不把它称为密码学秘钥。compiler 目标加载接口为 `emitVMTargetLoad(IRBuilder<>& B, Value* Table, Value* SlotIndex, Value* Descriptor, const Twine& Name) -> Value*`。

- [ ] 写 C++ roundtrip 边界测试及最小 blockaddress PIE 探针，覆盖地址低于 slot、ASLR、多对象和 `--gc-sections`。

```cpp
TEST(VMTargetEncoding, NegativeRelativeTarget) {
    constexpr uint64_t Slot = 0x1000, Target = 0x800;
    auto E = encodeVMTarget(Target-Slot, 0x123456789abcdef0ULL, 17, 23);
    EXPECT_EQ(Slot + decodeVMTarget(E, 0x123456789abcdef0ULL, 17, 23), Target);
}
```

- [ ] 红测：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_target_encoding.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-target-probe-red`。
- [ ] probe 证明 raw target 可在 final ELF 定位且 load bias 可消除后，生成待封装描述符。未知平台若显式 encodedTargets 则编译失败；不要产出假保护。
- [ ] runtime 先检查 processed state，再按需解码一个槽；engine 入口单独 descriptor，不占 OP_COUNT*K。中央/threaded tail 统一调用上述 emitVMTargetLoad 接口。
- [ ] 验证未封装执行拒绝、编码数学 roundtrip、descriptor bounds；在 hardener 接入前不改变 max 默认值。

### Task 8：hardener 封装、重定位处理与最终 ELF 门禁

**Files:** 新建 `tools/xollvm-elf-hardener/VMTargets.h/.cpp`；修改 hardener `.cpp`、CMake；扩展 `utils/test_vm_target_encoding.py`。

**Interfaces:** `finalizeVMTargets(MutableArrayRef<uint8_t> Image) -> Error`；`verifyVMTargets(ArrayRef<uint8_t> Image) -> Error`。CLI 新命令 `targets --input PATH --output PATH`；seal 内部先调用 finalize，再 hash；audit/verify 对待处理 targets 返回明确错误。

- [ ] 用 Task 7 PIE 产生 raw slot，调用 targets，独立 Python 解码检查指向预期 executable range；执行封装前拒绝、封装后与基线一致。
- [ ] 红测 Task 7 命令 basetemp=`max-target-final-red`。
- [ ] 处理普通 RELA、Android APS2 packed RELA 和 RELR：解码到统一 relocation 集合；只剔除 descriptor 所属槽的相对 relocation，重新编码合法输出。格式未知或绝对外部 relocation 指向该槽则拒绝，不能留下动态恢复原指针的条目。
- [ ] 两遍处理：第一遍验证所有 descriptor/range/overlap/reloc 并计算改写，第二遍一次性输出；失败不修改输入，processed state 最后写入。清除用于处理的 raw addresses，保留运行必需编码参数。
- [ ] 测试无 manifest、有 manifest、重复 targets、重复 seal、坏版本/overlap、stripped、GC、多 archive、输出等于输入、truncated ELF。strip 后 verify 保持 manifest 范围一致；strip 必须在 seal 前进行。
- [ ] 运行绿测；对 final ELF 显式检查 descriptor 数据区/所有动态 relocation 无原始目标槽，并检查不同 seed 布局差异。

### Task 9：正式安装链接入口

**Files:** 新建 `tools/xollvm-link`；修改根 CMake、`utils/test_toolchain_packaging.py`；新建 `utils/test_vm_link_delivery.py`；更新 `docs/obf_annotations.h`。

**Consumes:** Task 8 CLI。**Produces:** 已安装可执行 wrapper，Termux 和 MT 均使用显式 bash，解释器路径可由包装环境指定；link compiler 和 hardener 路径通过参数/环境明确配置，不依赖 demo。

- [ ] 写实际链接测试，用相同已编译对象验证成功原子推广；hardener 缺失、targets 错误、audit/seal/verify 错误各保留原输出。

```python
def test_failed_finalize_preserves_previous_output(tmp_path):
    out = tmp_path / 'app'
    out.write_bytes(b'previous-output')
    proc = invoke_link_wrapper(tmp_path, output=out, hardener='/missing/hardener')
    assert proc.returncode != 0
    assert out.read_bytes() == b'previous-output'
```

invoke_link_wrapper 在本文件用真实 clang+Task 7 fixture 定义，不 mock 链接步骤；专门的故障注入 wrapper 只用于验证下游非零退出的传播。

- [ ] 红测：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_link_delivery.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-link-red`。
- [ ] 实现参数数组保留、带空格路径、同目录唯一临时输出、trap cleanup 和 link→targets→audit→seal→verify→atomic rename；没有 sensitive manifest 时 verify 仍检查 targets，不能尝试不存在的 digest。
- [ ] 安装到正式工具目录并加入发布打包检查；运行组件安装到临时 prefix 后的工具，不只检查源码字符串。绿测和现有 packaging suite。

### Task 10：白盒 AES 生成、已知答案与 VM 接入

**Files:** 新建 `VMWhiteBoxAES.h/.cpp`、`VMPass_WhiteBox.cpp`、`utils/test_vm_whitebox_aes.py`；修改 Crypto、Wrapper、Decode、Impl、配置/key、CMake；扩展 `VMRequirementsTest.cpp`。

**Interfaces:** `VMWhiteBoxAES::generate(ArrayRef<uint8_t> Key16, uint64_t Seed) -> Expected<VMWhiteBoxTables>`；`VMWhiteBoxAES::evaluate(const VMWhiteBoxTables&, ArrayRef<uint8_t> Input16) -> std::array<uint8_t,16>`；`emitVMWhiteBoxInstance(Module&, const VMWhiteBoxTables&) -> GlobalVariable*`；目标轮函数输入 instance+nonce+blockIndex+output，不输入 expanded key。

- [ ] C++ 首先写 AES FIPS 已知答案：key=`000102030405060708090a0b0c0d0e0f`，input=`00112233445566778899aabbccddeeff`，output=`69c4e0d86a7b0430d8cdb78070b4c55a`。再以 100 个随机 key/input 和现有标准 AES 参照比较。
- [ ] 红测 C++ target（缺少 generate/evaluate）；实现 9 轮 key-fused MixColumns 表、末轮表、内部字节编码和编码 nibble-XOR 网络。编码关系全部由 generator 生成，同 key不同 seed 输出一致而表不同。
- [ ] 已知答案绿测后生成 LLVM IR 轮执行函数；仅 private table/函数，无标准 roundkey global 和 XOR 配对恢复流程。用独立 native fixture 对同一已知答案再验证目标代码。
- [ ] 新白盒 lazy layout 与旧普通 AES layout 分离，decode context 明确后端。bulk 与 lazy 使用同一白盒 CTR block 接口；nonce/counter 按现有标准字节序构造。
- [ ] 写以下缓存/并发测试；当前 lazyAESByte 每 byte 调用 keystream，不能声称已有真正命中缓存，须实现 block miss 条件和正确 dominance：

```python
@pytest.mark.parametrize('indices,calls', [([0,1,15],1), ([15,16,17],2), ([31,0,31],3)])
def test_lazy_cache(indices, calls, tmp_path):
    exe = build_whitebox_fetch_fixture(tmp_path, indices, count_calls=True)
    run_case(exe, (), f'correct calls={calls}\n')
```

build_whitebox_fetch_fixture 使用真实解码/白盒执行，仅在测试 IR 中插入调用计数，不给 production 添加 debug count。边界长度 0/1/15/16/17、逆向 seek、递归和 8 线程测试比较解密结果。

- [ ] 红/绿命令：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_whitebox_aes.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-whitebox-green`；验证 CALL、不同 key共享 engine、多编译单元、unused table GC。
- [ ] 以保护对象的 known build-time key 检查最终 VM IR/ELF 不存在完整 expanded key及配对 mask；测试不能因 StringEncryption 的独立 key误判，也不能只查符号名称。

### Task 11：嵌套 owner 隔离、内层 hardening 与响应绑定

**Files:** 修改 Nested、Impl、Plan、AntiDebug、Harden、Wrapper、配置/key；新建 `utils/test_vm_nested_hardening.py`。

**Produces:** helper key=`(outerEngineKey, logicalOpcode, innerLayer)`；inner engine 保留 owner，不强制 pool 0；`nestedVMHardened` 实际生效；有效 AntiDebugConfig 在构建 VM 前合并，key/bytecode decode 绑定共享响应状态。

- [ ] 构造同模块两个 nested 函数，分别 StrongBC/lazy/whitebox/layout不同，helper 不混用；native输出和 LLVM verifier 均正确。
- [ ] 重现小 helper wrapper dominance 失败，并写 depth=2 的 call graph 检查：inner body 不可回调同一 nested helper。
- [ ] 红测：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_nested_hardening.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-nested-red`。
- [ ] 修复支配关系，InnerCfg.nestedVM=false；使用 outer effective 检测状态，内层不再启动监控线程。whitebox 路径的 detected response 作用于编码输入/解码状态，不恢复标准 key。
- [ ] helper失败纳入提交结果；strict/no-skips失败中止，普通可选模式报告真实失败，不将 native helper留存视为成功嵌套。
- [ ] 同上绿测，包含 clean/latched-detected、并发销毁、不启用检测时的绑定关闭原因，及现有 AntiDebug 生命周期 suite。

### Task 12：max 生效、完整报告与组合回归

**Files:** 修改 VMPass.cpp、ObfuscationConfig.h、Requirements、ObfReport、docs/obf_annotations.h；新建 `utils/test_vm_max_config.py`、`utils/test_vm_max_composition.py`。

**Produces:** max 开启 extendedISA、operandLayout、encodedTargets、whiteboxAES、nestedVMHardened、wrapperFamily=auto；cloudDispatch仍显式 opt-in。请求/有效/依赖原因结构化报告，包含实际 handler/variant/helper/whitebox数量和需后处理状态。

- [ ] 写 preset/显式覆盖组合 tests，未知 preset/参数值拒绝或给明确诊断，不能悄悄忽略请求保护。

```python
def test_explicit_disable_overrides_max(tmp_path):
    report = transform_report(tmp_path, 'vm(preset=max,whiteboxAES=0,encodedTargets=0)')
    assert report['effective']['whiteboxAES'] is False
    assert report['effective']['encodedTargets'] is False
    assert report['effective']['extendedISA'] is True
```

transform_report 用真实 opt `-obf-report-json`，在本文件定义读取实际函数报告；报告中的 post-link pending 不能由 compile阶段伪报 completed。

- [ ] 红测：`PYTHONDONTWRITEBYTECODE=1 python -m pytest utils/test_vm_max_config.py utils/test_vm_max_composition.py -x -q -p no:cacheprovider --basetemp=/data/data/com.termux/files/usr/tmp/opencode/max-compose-red`。
- [ ] 增加新增布尔字段、白盒/目标/layout版本到 EngineConfigKey；bindAntiDebug 依据合并配置处理，关闭原因具名。报告 wrapperFamily实际选择而非 auto 字面值。
- [ ] 全组合样本：中央/threaded、shared/perFn engine、nested on/off、普通/白盒、bulk/lazy、CALL 5返回类别、ELF sensitive on/off、seed 1/42/20260930、clang -O0/-O2。不同 key/owner不能共享错引擎。
- [ ] 更新现有 max 测试使用正式后处理流程；保留专门的未封装负例。云值测试用独立本地 fixture，不接实际服务器。
- [ ] 重建、执行本文件标准全量命令与安装组件验证；任何原有测试失败逐项解释并修复，不能批量换成 medium绕过 max。

### Task 13：最终 AArch64 抗分析检查和开销测量

**Files:** 新建 `utils/deobf_bench/attacks/aarch64_vm_targets.py`、`aarch64_vm_bytecode.py`、`utils/deobf_bench/__main__.py`、`utils/vm_hardening_cost.py`；修改 deobf runner/report/CLI；新建测试 `utils/test_vm_attack_results.py`。

**Interfaces:** AttackResult 的 status/technique/detail 区分 `RECOVERED`、`NOT_RECOVERED_WITHIN_BUDGET`、`TIMEOUT`、`UNSUPPORTED`、`TOOL_ERROR`；成本 JSON 包含 seed/config/fixture、wallTime、maxRSS、textBytes、rodataBytes、relocBytes、runtimeNs。报告保留现有兼容字段但不把错误映射为 resilience=1。

- [ ] 先写结果分类负例：工具崩溃、缺依赖、超时都不是安全成功。测试实际 subprocess状态转换，不依赖 mock评分。
- [ ] 保留现有 `--attacks` 和 `--build-dir` 接口，增加模块入口：`PYTHONPATH=utils python -m utils.deobf_bench --build-dir /data/user/0/com.termux/files/home/xollvm-android/build-sensitive --attacks aarch64-vm-targets --seeds 1,42,20260930 --case-timeout 180 --work /data/data/com.termux/files/usr/tmp/opencode/max-vm-attack-targets --json-report /data/data/com.termux/files/usr/tmp/opencode/max-vm-attack-targets.json`；第二次使用 `--attacks aarch64-vm-bytecode`，work/report 分别改为 max-vm-attack-bytecode。CLI 不得递归删除用户指定的现存 work，新增运行唯一子目录。
- [ ] fixture仅向攻击阶段提供 stripped final ELF和可公开输入输出；不传 obf.ll、编译seed、key、明文字节码或原始 descriptor。攻击用 ELF解析和 AArch64反汇编追踪数据关系；真实动态工具不可用必须标 unsupported，不伪造抗性结果。
- [ ] 成本 CLI：`python utils/vm_hardening_cost.py --baseline-opt /data/data/com.termux/files/usr/tmp/opencode/max-vm-baseline/opt --current-opt /data/user/0/com.termux/files/home/xollvm-android/build-sensitive/bin/opt --seeds 1,42,20260930 --timeout 180 --output /data/data/com.termux/files/usr/tmp/opencode/max-vm-cost.json`。实施 Task 1 前保存当前正式 opt/clang/hardener 副本，记录版本、源码 HEAD 和未提交 patch hash；不重编旧 LLVM、不覆盖正式工具、不读取凭据，目录父级先验证。复用原 NDK 执行 baseline IR 的降级编译，确保两组相同后端参数。
- [ ] 选定无凭据算术、分支、访存、CALL、nested 5组样本，记录 old/new max的真实差值；重型单样本 timeout后停止该样本，不无限重试。
- [ ] 完成最终 artifacts 的 audit/targets verify/seal digest检查、全量 Python/C++、安装及工作区 diff审阅；交付结果说明新增能力、实际开销、攻击未覆盖项和未提交文件。

## 自审结论与执行交接

- ISA 40个新增指令域划分：18+16+6=40；0x38..0x5f恰好40个，OP_COUNT=0x60。
- 每个新配置都有 compiler key、请求/有效报告、显式覆盖及错误路径任务。
- handler保护包含后处理、动态 relocation、正式安装链接流程和缺少 manifest 的处理，不只改 LLVM IR。
- 白盒包含标准 AES已知答案、目标执行、lazy/bulk、缓存隔离及不同 key实例，不以分片 key替代。
- CALL与nested修复都有真实 native组合回归；已有用户工作和未提交修复不被覆盖。
- baseline工具副本必须在实施开始时保存，Task 13依赖该基线；未得到用户执行选择前不创建工作树或开始产品改动。
- 计划按依赖串行执行；推荐本会话直接实现，减少共享 ABI/layout/descriptor接口的交接成本。用户选择委派时才启动 subagent。
