"""Encrypted artifact boundary tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_artifact_builder_does_not_store_plaintext_payload(tmp_path):
    source = tmp_path / "artifact_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/dynamic_vm_artifact.h"\n'
        '#include "runtime/cloud_material/dynamic_vm_shard.h"\n'
        '#include <cassert>\n'
        '#include <string>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  ArtifactSource source{}; source.build_id[0] = 1; source.region_id[0] = 2;\n'
        '  source.artifact_key[0] = 3; source.bytecode = {0x70, 0x6c, 0x61, 0x69, 0x6e};\n'
        '  auto code = buildAarch64ReturnIntShard(0, 1);\n'
        '  if (!code) return 0;\n'
        '  HandlerShardDescriptor descriptor{}; descriptor.shard_id = 1; descriptor.code_size = code->size(); descriptor.commitment = hashAarch64ShardCode(*code);\n'
        '  source.handler_shards = encodeHandlerShardPayload(descriptor, *code);\n'
        '  auto artifact = buildEncryptedVmArtifact(source);\n'
        '  assert(artifact);\n'
        '  const auto encoded = encodeEncryptedVmArtifact(*artifact);\n'
        '  assert(!encoded.empty());\n'
        '  assert(std::search(encoded.begin(), encoded.end(), source.bytecode.begin(), source.bytecode.end()) == encoded.end());\n'
        '  assert(std::search(encoded.begin(), encoded.end(), source.handler_shards.begin(), source.handler_shards.end()) == encoded.end());\n'
        '  auto decrypted = decryptEncryptedVmArtifact(*artifact, source.artifact_key, source.build_id, source.region_id);\n'
        '  assert(decrypted); assert(decrypted->bytecode == source.bytecode); assert(decrypted->handler_shards == source.handler_shards);\n'
        '  auto tampered = *artifact; tampered.encrypted_handler_shards[15] ^= 1;\n'
        '  assert(!decryptEncryptedVmArtifact(tampered, source.artifact_key, source.build_id, source.region_id));\n'
        '  auto tampered_descriptor = *artifact; tampered_descriptor.continuation_descriptors.push_back(1);\n'
        '  assert(!decryptEncryptedVmArtifact(tampered_descriptor, source.artifact_key, source.build_id, source.region_id));\n'
         '  auto split_a = source; split_a.continuation_descriptors = {1};\n'
         '  auto split_b = source; split_b.continuation_descriptors = {1, 2};\n'
        '  auto artifact_a = buildEncryptedVmArtifact(split_a); auto artifact_b = buildEncryptedVmArtifact(split_b);\n'
        '  assert(artifact_a && artifact_b && artifact_a->artifact_hash != artifact_b->artifact_hash);\n'
        '  auto wrong_region = source.region_id; wrong_region[0] ^= 1;\n'
        '  assert(!decryptEncryptedVmArtifact(*artifact, source.artifact_key, source.build_id, wrong_region));\n'
         '  auto malformed = source; malformed.handler_shards = {1, 2, 3};\n'
         '  assert(!buildEncryptedVmArtifact(malformed));\n'
         '  auto inconsistent = source;\n'
         '  HandlerShardDescriptor inconsistent_descriptor = descriptor; inconsistent_descriptor.relocation_count = 1;\n'
         '  inconsistent.handler_shards = encodeHandlerShardPayload(inconsistent_descriptor, *code);\n'
         '  assert(!buildEncryptedVmArtifact(inconsistent));\n'
             '  auto oversized = source; oversized.bytecode.assign(kDynamicVmMaxWindowMaterial * 64 + 1, 1);\n'
         '  assert(!buildEncryptedVmArtifact(oversized));\n'
         '  auto oversized_descriptors = source; oversized_descriptors.continuation_descriptors.assign(kDynamicVmMaxDescriptor + 1, 1);\n'
         '  assert(!buildEncryptedVmArtifact(oversized_descriptors));\n'
        '  secureClear(*decrypted); assert(decrypted->bytecode.empty()); assert(decrypted->handler_shards.empty());\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/dynamic_vm_artifact.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_shard.cpp"), "-lcrypto", "-o", str(exe)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
