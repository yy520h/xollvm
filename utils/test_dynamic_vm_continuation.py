"""Continuation execution must use local authenticated tails, not opcode tables."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_continuation_executor_runs_authenticated_local_chain(tmp_path):
    source = tmp_path / "continuation_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/continuation_executor.h"\n'
        '#include "runtime/cloud_material/dynamic_vm_schema.h"\n'
        '#include "runtime/cloud_material/integrity_state.h"\n'
        '#include <cassert>\n'
        '#include <vector>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  std::vector<int> trace;\n'
        '  ContinuationExecutor executor;\n'
        '  ContinuationNode first{1, 2, [&](uint64_t) { trace.push_back(1); return true; }};\n'
        '  ContinuationNode second{2, 0, [&](uint64_t) { trace.push_back(2); return true; }};\n'
         '  assert(executor.runWindow({first, second}, 1));\n'
         '  assert((trace == std::vector<int>{1, 2}));\n'
         '  trace.clear(); assert(!executor.runWindow({first, second}, 0)); assert(trace.empty());\n'
        '  WindowGrant grant{}; grant.generation = 2; grant.window_id = 3; grant.issued_at_ms = 10; grant.expires_at_ms = 20; grant.previous_state_hash[0] = 4; grant.next_state_hash[0] = 5; grant.build_id[0] = 6; grant.region_id[0] = 7; grant.session_id[0] = 8;\n'
        '  WindowBinding binding{}; binding.build_id = grant.build_id; binding.region_id = grant.region_id; binding.session_id = grant.session_id; binding.generation = 2; binding.window_id = 3; binding.previous_state_hash = grant.previous_state_hash; binding.now_ms = 15;\n'
        '  ContinuationWindow window{}; window.state_hash = grant.previous_state_hash; window.window_id = 3; window.authenticated_bytes = {1};\n'
        '  trace.clear(); assert(executor.runWindow(window, grant, binding, {first, second}, 1)); assert((trace == std::vector<int>{1, 2})); assert(binding.previous_state_hash == grant.next_state_hash);\n'
        '  window.state_hash[0] = 9; trace.clear(); assert(!executor.runWindow(window, grant, binding, {first, second}, 1)); assert(trace.empty());\n'
        '  IntegrityState integrity(grant.previous_state_hash);\n'
        '  auto expected = integrity.commit(grant, grant.next_state_hash, grant.window_id, 1); assert(expected);\n'
        '  auto changed = integrity.commit(grant, grant.next_state_hash, grant.window_id, 2); assert(changed && *changed != *expected);\n'
        '  assert(integrity.advance(grant, grant.next_state_hash, grant.window_id, 1)); assert(integrity.value() == grant.next_state_hash);\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
             str(source), str(ROOT / "runtime/cloud_material/continuation_executor.cpp"),
             str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
             str(ROOT / "runtime/cloud_material/integrity_state.cpp"),
             "-lcrypto",
             "-o", str(exe)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
