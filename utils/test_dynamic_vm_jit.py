"""W^X handler buffer and continuation-tail tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_jit_buffer_transitions_without_rwx(tmp_path):
    source = tmp_path / "jit_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/jit_handler_buffer.h"\n'
        '#include <cassert>\n'
        '#include <span>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  assert(!JitHandlerBuffer::allocate(0));\n'
        '  assert(!JitHandlerBuffer::allocate(static_cast<size_t>(-1)));\n'
        '  auto buffer = JitHandlerBuffer::allocate(4096); assert(buffer);\n'
        '  const unsigned char bytes[] = {1, 2, 3, 4};\n'
        '  assert(buffer->write(bytes)); assert(buffer->sealExecutable());\n'
        '  assert(buffer->isExecutable() && !buffer->isWritable());\n'
        '  assert(buffer->makeWritable()); assert(buffer->isWritable());\n'
        '  assert(buffer->scrub()); assert(!buffer->isExecutable());\n'
        '  const unsigned char code[] = {1, 2, 3, 4};\n'
        '  assert(buffer->loadAndSeal(code, std::span<const unsigned char>{}));\n'
        '  assert(buffer->isExecutable() && !buffer->isWritable());\n'
        '  assert(buffer->close()); assert(buffer->isClosed());\n'
        '  assert(!buffer->isExecutable() && !buffer->isWritable());\n'
        '  assert(buffer->close()); assert(!buffer->write(bytes));\n'
        '  auto rejected = JitHandlerBuffer::allocate(4096); assert(rejected);\n'
        '  const unsigned char bad_size[] = {0}; assert(!rejected->loadAndSeal(code, bad_size));\n'
         '  const unsigned char bad_kind[] = {0, 0, 0, 0, 0, 2, 0, 0}; assert(!rejected->loadAndSeal(code, bad_kind));\n'
         '  const unsigned char unaligned_target[] = {0, 0, 0, 2, 0, 1, 0, 4}; assert(!rejected->loadAndSeal(code, unaligned_target));\n'
         '  const unsigned char supported_but_unimplemented[] = {0, 0, 0, 0, 0, 1, 0, 4}; assert(!rejected->loadAndSeal(code, supported_but_unimplemented));\n'
         '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/jit_handler_buffer.cpp"),
         "-pthread", "-o", str(exe)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
