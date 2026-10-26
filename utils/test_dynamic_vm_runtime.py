"""Authenticated dynamic artifact/window runtime consumer tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_dynamic_runtime_consumes_only_contiguous_authenticated_windows(tmp_path):
    source = tmp_path / "dynamic_runtime_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/dynamic_vm_runtime.h"\n'
        '#include "runtime/cloud_material/dynamic_vm_artifact.h"\n'
        '#include "runtime/cloud_material/dynamic_vm_window_provider.h"\n'
        '#include "runtime/cloud_material/dynamic_vm_shard.h"\n'
        '#include <array>\n'
        '#include <cassert>\n'
        '#include <cstring>\n'
        '#include <span>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  ArtifactSource source{}; source.build_id[0] = 1; source.region_id[0] = 2;\n'
        '  source.artifact_key.fill(3); source.bytecode = {7, 8, 9};\n'
        '  auto code = buildAarch64ReturnIntShard(0, 1); if (!code) return 0;\n'
        '  HandlerShardDescriptor descriptor{}; descriptor.shard_id = 1; descriptor.code_size = code->size(); descriptor.commitment = hashAarch64ShardCode(*code);\n'
        '  source.handler_shards = encodeHandlerShardPayload(descriptor, *code);\n'
        '  DynamicVmShardContext::ProgramDescriptor program; program.load_opcode = 0; program.ret_opcode = 13; program.supported = true;\n'
        '  source.continuation_descriptors = encodeProgramDescriptor(program);\n'
        '  auto artifact = buildEncryptedVmArtifact(source); if (!artifact) return 0;\n'
        '  std::array<unsigned char, 16> session{}; session.fill(4);\n'
        '  DynamicHash initial{}; initial[0] = 10;\n'
        '  auto consumer = DynamicVmWindowConsumer::create(*artifact, source.build_id, source.region_id, session, initial);\n'
        '  assert(consumer);\n'
        '  auto tampered_artifact = *artifact; tampered_artifact.encrypted_handler_shards[0] ^= 1;\n'
        '  assert(!DynamicVmWindowConsumer::create(tampered_artifact, source.build_id, source.region_id, session, initial));\n'
        '  auto tampered_descriptor = *artifact; tampered_descriptor.continuation_descriptors.push_back(1);\n'
        '  assert(!DynamicVmWindowConsumer::create(tampered_descriptor, source.build_id, source.region_id, session, initial));\n'
        '  WindowMaterial material{}; material.window[0] = 11; material.jit[0] = 12; material.integrity[0] = 13;\n'
        '  std::vector<unsigned char> bytes(sizeof(material)); std::memcpy(bytes.data(), &material, sizeof(material));\n'
        '  WindowRequest request{}; request.build_id = source.build_id; request.region_id = source.region_id; request.session_id = session;\n'
        '  request.session_secret.fill(9); request.generation = 1; request.window_id = 1; request.previous_state_hash = initial; request.next_state_hash[0] = 20;\n'
        '  request.now_ms = 100; request.expires_at_ms = 200; request.key_version = 1; request.material = bytes;\n'
        '  auto grant = issueWindowGrant(request); assert(grant);\n'
        '  auto consumed = consumer->consume(*grant, request.session_secret, 150, 7); assert(consumed);\n'
        '  assert((*consumed).window[0] == 11 && (*consumed).jit[0] == 12);\n'
        '  assert(consumer->integrityCommitment() != DynamicHash{});\n'
        '  assert(!consumer->consume(*grant, request.session_secret, 150));\n'
        '  WindowGrant skipped = *grant; skipped.generation = 3; skipped.window_id = 3; skipped.previous_state_hash[0] = 20; skipped.next_state_hash[0] = 30;\n'
        '  assert(!consumer->consume(skipped, request.session_secret, 150));\n'
        '  WindowGrant expired = *grant; expired.generation = 2; expired.window_id = 2; expired.previous_state_hash[0] = 20; expired.next_state_hash[0] = 30;\n'
        '  assert(!consumer->consume(expired, request.session_secret, 200));\n'
        '  auto tampered = *grant; tampered.generation = 2; tampered.window_id = 2; tampered.previous_state_hash[0] = 20; tampered.next_state_hash[0] = 30; tampered.encrypted_window_material.back() ^= 1;\n'
        '  assert(!consumer->consume(tampered, request.session_secret, 150));\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/dynamic_vm_runtime.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_artifact.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
              str(ROOT / "runtime/cloud_material/dynamic_vm_window_provider.cpp"),
              str(ROOT / "runtime/cloud_material/dynamic_vm_shard.cpp"),
              str(ROOT / "runtime/cloud_material/jit_handler_buffer.cpp"),
             str(ROOT / "runtime/cloud_material/integrity_state.cpp"),
         "-lcrypto", "-o", str(exe)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr


def test_dynamic_runtime_rejects_unsupported_or_tampered_execution_material(tmp_path):
    source = tmp_path / "dynamic_execution_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/dynamic_vm_runtime.h"\n'
        '#include "runtime/cloud_material/dynamic_vm_artifact.h"\n'
        '#include "runtime/cloud_material/dynamic_vm_shard.h"\n'
        '#include <cassert>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  ArtifactSource source{}; source.build_id[0] = 1; source.region_id[0] = 2; source.artifact_key.fill(3);\n'
        '  source.bytecode = {0, 0, 7, 0, 0, 0, 13, 0};\n'
        '  auto code = buildAarch64BridgeShard(); if (!code) return 0;\n'
        '  HandlerShardDescriptor descriptor{}; descriptor.shard_id = 1; descriptor.code_size = code->size(); descriptor.commitment = hashAarch64ShardCode(*code);\n'
        '  source.handler_shards = encodeHandlerShardPayload(descriptor, *code);\n'
        '  auto artifact = buildEncryptedVmArtifact(source); if (!artifact) return 0;\n'
        '  auto result = executeDynamicVmArtifact(*artifact, source.artifact_key, source.build_id, source.region_id);\n'
        '  if (result) assert(result->status == XOVM_SHARD_ABORT);\n'
        '  auto tampered = *artifact; tampered.artifact_hash[0] ^= 1;\n'
        '  assert(!executeDynamicVmArtifact(tampered, source.artifact_key, source.build_id, source.region_id));\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/dynamic_vm_runtime.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_artifact.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_shard.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_window_provider.cpp"),
         str(ROOT / "runtime/cloud_material/integrity_state.cpp"),
         str(ROOT / "runtime/cloud_material/jit_handler_buffer.cpp"),
         "-lcrypto", "-o", str(exe)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
