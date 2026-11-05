"""Exact-template and execution tests for AArch64 dynamic VM shards."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SHARD_CPP = ROOT / "runtime/cloud_material/dynamic_vm_shard.cpp"
JIT_BUFFER_CPP = ROOT / "runtime/cloud_material/jit_handler_buffer.cpp"


def _compile(source: Path, output: Path, *extra_flags: str) -> None:
    result = subprocess.run(
        [
            "c++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            *extra_flags,
            "-I",
            str(ROOT),
            str(source),
            str(SHARD_CPP),
            str(JIT_BUFFER_CPP),
            "-lcrypto",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def _run(executable: Path) -> None:
    result = subprocess.run(
        [str(executable)], capture_output=True, text=True, timeout=5
    )
    assert result.returncode == 0, result.stderr


def test_aarch64_shards_match_exact_templates_and_use_frozen_context(tmp_path):
    source = tmp_path / "shard_probe.cpp"
    source.write_text(
        r'''#include "runtime/cloud_material/dynamic_vm_shard.h"
#include "runtime/cloud_material/jit_handler_buffer.h"
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    using namespace xovm::material;

    const std::vector<uint8_t> expected_load = {
        0x01, 0x04, 0x40, 0xf9, 0x02, 0xcf, 0x8a, 0x52,
        0x82, 0x46, 0xa2, 0x72, 0x22, 0x04, 0x00, 0xb9,
        0xa3, 0x00, 0x80, 0x52, 0x03, 0x20, 0x00, 0xb9,
        0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    };
    const std::vector<uint8_t> expected_return = {
        0x01, 0x04, 0x40, 0xf9, 0x02, 0x0c, 0x40, 0xf9,
        0x23, 0x04, 0x40, 0xb9, 0x43, 0x00, 0x00, 0xb9,
        0x43, 0x00, 0x80, 0x52, 0x03, 0x20, 0x00, 0xb9,
        0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    };
    const std::vector<uint8_t> expected_combined = {
        0x01, 0x04, 0x40, 0xf9, 0x02, 0xcf, 0x8a, 0x52,
        0x82, 0x46, 0xa2, 0x72, 0x22, 0x04, 0x00, 0xb9,
        0x02, 0x0c, 0x40, 0xf9, 0x23, 0x04, 0x40, 0xb9,
        0x43, 0x00, 0x00, 0xb9, 0x03, 0x01, 0x80, 0x52,
        0x03, 0x20, 0x00, 0xb9, 0x20, 0x00, 0x80, 0x52,
        0xc0, 0x03, 0x5f, 0xd6,
    };

    auto load = buildAarch64LoadImmediateShard(1, 0x12345678, 5);
    auto ret = buildAarch64ReturnIntShard(1, 2);
    auto combined = buildAarch64LoadAndReturnIntShard(1, 0x12345678, 1, 8);
    assert(load && *load == expected_load);
    assert(ret && *ret == expected_return);
    assert(combined && *combined == expected_combined);

    assert(validateAarch64LoadImmediateShard(*load, 1, 0x12345678, 5));
    assert(validateAarch64ReturnIntShard(*ret, 1, 2));
    assert(validateAarch64LoadAndReturnIntShard(
        *combined, 1, 0x12345678, 1, 8));
    assert(validateAarch64ShardTemplate(
        *combined, Aarch64ShardTemplate::LoadAndReturnInt,
        {1, 0x12345678, 1, 8}));
    assert(validateAarch64Shard(*load));
    assert(validateAarch64Shard(*ret));
    assert(validateAarch64Shard(*combined));

    assert(!validateAarch64LoadImmediateShard(*load, 0, 0x12345678, 5));
    assert(!validateAarch64LoadImmediateShard(*load, 1, 0x12345679, 5));
    assert(!validateAarch64LoadImmediateShard(*load, 1, 0x12345678, 6));
    assert(!validateAarch64ReturnIntShard(*ret, 0, 2));
    assert(!validateAarch64ReturnIntShard(*ret, 1, 3));
    assert(!validateAarch64LoadAndReturnIntShard(
        *combined, 1, 0x12345678, 0, 8));
    assert(!validateAarch64ShardTemplate(
        *combined, Aarch64ShardTemplate::ReturnInt, {0, 0, 1, 8}));

    auto mutated = *load;
    mutated[0] ^= 1;
    assert(!validateAarch64Shard(mutated));
    auto extra_allowed_instruction = *load;
    extra_allowed_instruction.insert(extra_allowed_instruction.end(),
                                     {0xc0, 0x03, 0x5f, 0xd6});
    assert(!validateAarch64Shard(extra_allowed_instruction));
    auto arbitrary_concatenation = *load;
    arbitrary_concatenation.insert(
        arbitrary_concatenation.end(), ret->begin(), ret->end());
    assert(!validateAarch64Shard(arbitrary_concatenation));
    auto program_load = buildAarch64LoadImmediateShard(1, 0x12345678, 6);
    auto program_ret = buildAarch64ReturnIntShard(1, 8);
    assert(program_load && program_ret);
    auto canonical_program = *program_load;
    canonical_program.insert(
        canonical_program.end(), program_ret->begin(), program_ret->end());
    assert(validateAarch64Shard(canonical_program));
    canonical_program.insert(
        canonical_program.end(), program_ret->begin(), program_ret->end());
    assert(!validateAarch64Shard(canonical_program));
    const std::vector<uint8_t> broad_class_sequence = {
        0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    };
    assert(!validateAarch64Shard(broad_class_sequence));

    auto high_register_load = buildAarch64LoadImmediateShard(249, 7, 0xffffffffu);
    auto high_register_ret = buildAarch64ReturnIntShard(249, 0xffffffffu);
    assert(high_register_load && high_register_ret);
    assert(validateAarch64LoadImmediateShard(
        *high_register_load, 249, 7, 0xffffffffu));
    assert(validateAarch64ReturnIntShard(
        *high_register_ret, 249, 0xffffffffu));
    assert(validateAarch64Shard(*high_register_load));
    assert(validateAarch64Shard(*high_register_ret));
    assert(!buildAarch64LoadImmediateShard(250, 0, 0));
    assert(!buildAarch64ReturnIntShard(250, 0));
    assert(!buildAarch64LoadAndReturnIntShard(0, 0, 250, 0));
    assert(!validateAarch64LoadImmediateShard(expected_load, 250, 0, 0));
    assert(!validateAarch64ReturnIntShard(expected_return, 250, 0));
    assert(!validateAarch64LoadAndReturnIntShard(
        expected_combined, 0, 0, 250, 0));

    uint32_t registers[250] = {};
    uint32_t return_value = 0;
    XovmDynamicVmExecutionContext context{
        XOVM_DYNAMIC_VM_EXECUTION_CONTEXT_VERSION,
        XOVM_DYNAMIC_VM_EXECUTION_CONTEXT_SIZE,
        registers,
        250,
        &return_value,
        0,
        nullptr,
        0,
        nullptr,
    };

    auto load_buffer = JitHandlerBuffer::allocate(load->size());
    assert(load_buffer && load_buffer->isWritable() &&
           !load_buffer->isExecutable());
    assert(load_buffer->loadAndSeal(*load, {}));
    assert(!load_buffer->isWritable() && load_buffer->isExecutable());
    auto load_entry = reinterpret_cast<DynamicVmShardEntry>(load_buffer->address());
    assert(load_entry(&context) == XOVM_SHARD_CONTINUE);
    assert(registers[1] == 0x12345678);
    assert(context.instruction_pointer == 5);

    auto ret_buffer = JitHandlerBuffer::allocate(ret->size());
    assert(ret_buffer && ret_buffer->isWritable() && !ret_buffer->isExecutable());
    assert(ret_buffer->loadAndSeal(*ret, {}));
    assert(!ret_buffer->isWritable() && ret_buffer->isExecutable());
    auto ret_entry = reinterpret_cast<DynamicVmShardEntry>(ret_buffer->address());
    assert(ret_entry(&context) == XOVM_SHARD_RETURN);
    assert(return_value == 0x12345678);
    assert(context.instruction_pointer == 2);

    registers[0] = 0;
    registers[1] = 0;
    return_value = 0;
    context.instruction_pointer = 0;
    auto combined_buffer = JitHandlerBuffer::allocate(combined->size());
    assert(combined_buffer && combined_buffer->isWritable() &&
           !combined_buffer->isExecutable());
    assert(combined_buffer->loadAndSeal(*combined, {}));
    assert(!combined_buffer->isWritable() && combined_buffer->isExecutable());
    auto combined_entry =
        reinterpret_cast<DynamicVmShardEntry>(combined_buffer->address());
    assert(combined_entry(&context) == XOVM_SHARD_RETURN);
    assert(registers[1] == 0x12345678 && return_value == 0x12345678);
    assert(context.instruction_pointer == 8);

    auto high_load_buffer = JitHandlerBuffer::allocate(high_register_load->size());
    assert(high_load_buffer && high_load_buffer->loadAndSeal(*high_register_load, {}));
    auto high_load_entry =
        reinterpret_cast<DynamicVmShardEntry>(high_load_buffer->address());
    assert(high_load_entry(&context) == XOVM_SHARD_CONTINUE);
    assert(registers[249] == 7 && context.instruction_pointer == 0xffffffffu);
    auto high_ret_buffer = JitHandlerBuffer::allocate(high_register_ret->size());
    assert(high_ret_buffer && high_ret_buffer->loadAndSeal(*high_register_ret, {}));
    auto high_ret_entry =
        reinterpret_cast<DynamicVmShardEntry>(high_ret_buffer->address());
    assert(high_ret_entry(&context) == XOVM_SHARD_RETURN);
    assert(return_value == 7 && context.instruction_pointer == 0xffffffffu);

    return 0;
}
''',
        encoding="ascii",
    )
    executable = tmp_path / "shard_probe"
    _compile(source, executable)
    _run(executable)


def test_non_aarch64_builders_remain_unavailable(tmp_path):
    source = tmp_path / "non_aarch64_probe.cpp"
    source.write_text(
        r'''#include "runtime/cloud_material/dynamic_vm_shard.h"
#include <cassert>

int main() {
    using namespace xovm::material;
    assert(!buildAarch64LoadImmediateShard(0, 0, 0));
    assert(!buildAarch64ReturnIntShard(0, 0));
    assert(!buildAarch64LoadAndReturnIntShard(0, 0, 0, 0));
    return 0;
}
''',
        encoding="ascii",
    )
    executable = tmp_path / "non_aarch64_probe"
    _compile(source, executable, "-DXOVM_DYNAMIC_VM_TEST_NON_AARCH64=1")
    _run(executable)
