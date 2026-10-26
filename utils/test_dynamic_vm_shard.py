"""Executable AArch64 dynamic VM shard tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_aarch64_loadi_and_return_shards_execute_without_global_dispatch(tmp_path):
    source = tmp_path / "shard_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/dynamic_vm_shard.h"\n'
        '#include "runtime/cloud_material/jit_handler_buffer.h"\n'
        '#include <cassert>\n'
        '#include <cstdint>\n'
        '#include <vector>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  uint32_t regs[2] = {}; uint32_t result = 0;\n'
        '  DynamicVmShardContext context{}; context.regs = regs; context.reg_count = 2;\n'
        '  context.ret_storage = &result;\n'
        '  auto load = buildAarch64LoadImmediateShard(1, 0x12345678, 5); assert(load);\n'
        '  auto load_buffer = JitHandlerBuffer::allocate(load->size()); assert(load_buffer);\n'
        '  assert(load_buffer->loadAndSeal(*load, {}));\n'
        '  auto load_entry = reinterpret_cast<DynamicVmShardEntry>(load_buffer->address());\n'
        '  assert(load_entry(&context) == XOVM_SHARD_CONTINUE);\n'
        '  assert(regs[1] == 0x12345678);\n'
        '  assert(context.ip == 5);\n'
        '  context.callback = [](DynamicVmShardContext *ctx) -> uint32_t { ctx->ip = 9; return 7; };\n'
        '  auto bridge = buildAarch64BridgeShard(); assert(bridge);\n'
        '  auto bridge_buffer = JitHandlerBuffer::allocate(bridge->size()); assert(bridge_buffer);\n'
        '  assert(bridge_buffer->loadAndSeal(*bridge, {}));\n'
        '  auto bridge_entry = reinterpret_cast<DynamicVmShardEntry>(bridge_buffer->address());\n'
        '  assert(bridge_entry(&context) == 7 && context.ip == 9);\n'
        '  auto ret = buildAarch64ReturnIntShard(1, 2); assert(ret);\n'
        '  auto ret_buffer = JitHandlerBuffer::allocate(ret->size()); assert(ret_buffer);\n'
        '  assert(ret_buffer->loadAndSeal(*ret, {}));\n'
        '  auto ret_entry = reinterpret_cast<DynamicVmShardEntry>(ret_buffer->address());\n'
        '  assert(ret_entry(&context) == XOVM_SHARD_RETURN); assert(result == 0x12345678);\n'
        '  assert(context.ip == 2);\n'
        '  const unsigned char malformed[] = {0, 0, 0, 0, 0xc0, 0x03, 0x5f, 0xd6};\n'
        '  assert(!validateAarch64Shard(malformed));\n'
        '  DynamicVmShardContext::ProgramDescriptor descriptor{}; descriptor.supported = true;\n'
        '  auto encoded_descriptor = encodeProgramDescriptor(descriptor); assert(encoded_descriptor.size() == 18);\n'
        '  auto decoded_descriptor = decodeProgramDescriptor(encoded_descriptor); assert(decoded_descriptor && decoded_descriptor->supported);\n'
        '  encoded_descriptor[8] = 2; assert(!decodeProgramDescriptor(encoded_descriptor));\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/dynamic_vm_shard.cpp"),
         str(ROOT / "runtime/cloud_material/jit_handler_buffer.cpp"),
         "-lcrypto",
         "-o", str(exe)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stderr
