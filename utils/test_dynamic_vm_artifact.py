"""Encrypted artifact boundary tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_artifact_records_are_bounded_authenticated_and_graph_mapped(tmp_path):
    source = tmp_path / "artifact_probe.cpp"
    source.write_text(
        r'''
#include "runtime/cloud_material/dynamic_vm_artifact.h"
#include "runtime/cloud_material/dynamic_vm_shard.h"
#include <openssl/evp.h>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

using namespace xovm::material;

DynamicHash plainHash(std::span<const uint8_t> bytes) {
  DynamicHash result{};
  unsigned int size = 0;
  assert(EVP_Digest(bytes.data(), bytes.size(), result.data(), &size,
                    EVP_sha256(), nullptr) == 1);
  assert(size == result.size());
  return result;
}

ArtifactSource makeSource(bool two_nodes) {
  ArtifactSource source{};
  source.build_id[0] = 1;
  source.region_id[0] = 2;
  source.artifact_key[0] = 3;

  DynamicVmExecutionAbiV2 abi{};
  abi.abi_id = 7;
  abi.i32_register_count = 1;
  abi.loadi32_opcode = 0x0c;
  abi.return_i32_opcode = 0x0d;

  std::vector<uint8_t> raw_handlers;
  ContinuationGraphV2 graph{};
  graph.descriptor.abi_id = abi.abi_id;
  const auto abi_hash = hashDynamicVmExecutionAbiV2(abi);
  assert(abi_hash);
  graph.descriptor.abi_hash = *abi_hash;
  graph.descriptor.entry_node_id = 1;

  if (two_nodes) {
    source.bytecode = {0x0c, 0, 0x78, 0x56, 0x34, 0x12, 0x0d, 0};
    auto load = buildAarch64LoadImmediateShard(0, 0x12345678, 6);
    auto ret = buildAarch64ReturnIntShard(0, 8);
    assert(load && ret);
    raw_handlers = *load;
    raw_handlers.insert(raw_handlers.end(), ret->begin(), ret->end());

    ContinuationNodeV2 load_node{};
    load_node.node_id = 1;
    load_node.shard_id = 1;
    load_node.bytecode_size = 6;
    load_node.shard_size = static_cast<uint32_t>(load->size());
    load_node.next_node_id = 2;
    load_node.semantic = ContinuationNodeSemanticV2::LoadI32;
    load_node.status = ContinuationNodeStatusV2::Continue;
    load_node.variant_id = 1;
    load_node.bytecode_block_commitment = hashDynamicVmBytecodeBlockV2(
        std::span<const uint8_t>(source.bytecode).first(6));
    load_node.handler_shard_commitment = hashDynamicVmHandlerShardV2(*load);
    const auto load_tail = hashDynamicVmTransitionTailV2(load_node);
    assert(load_tail);
    load_node.transition_tail_commitment = *load_tail;

    ContinuationNodeV2 ret_node{};
    ret_node.node_id = 2;
    ret_node.shard_id = 2;
    ret_node.bytecode_offset = 6;
    ret_node.bytecode_size = 2;
    ret_node.shard_offset = static_cast<uint32_t>(load->size());
    ret_node.shard_size = static_cast<uint32_t>(ret->size());
    ret_node.semantic = ContinuationNodeSemanticV2::ReturnI32;
    ret_node.status = ContinuationNodeStatusV2::Return;
    ret_node.variant_id = 1;
    ret_node.bytecode_block_commitment = hashDynamicVmBytecodeBlockV2(
        std::span<const uint8_t>(source.bytecode).subspan(6));
    ret_node.handler_shard_commitment = hashDynamicVmHandlerShardV2(*ret);
    const auto ret_tail = hashDynamicVmTransitionTailV2(ret_node);
    assert(ret_tail);
    ret_node.transition_tail_commitment = *ret_tail;
    graph.nodes = {load_node, ret_node};
  } else {
    source.bytecode = {0x0d, 0};
    auto ret = buildAarch64ReturnIntShard(0, 2);
    assert(ret);
    raw_handlers = *ret;

    ContinuationNodeV2 ret_node{};
    ret_node.node_id = 1;
    ret_node.shard_id = 1;
    ret_node.bytecode_size = 2;
    ret_node.shard_size = static_cast<uint32_t>(ret->size());
    ret_node.semantic = ContinuationNodeSemanticV2::ReturnI32;
    ret_node.status = ContinuationNodeStatusV2::Return;
    ret_node.variant_id = 1;
    ret_node.bytecode_block_commitment =
        hashDynamicVmBytecodeBlockV2(source.bytecode);
    ret_node.handler_shard_commitment = hashDynamicVmHandlerShardV2(*ret);
    const auto tail = hashDynamicVmTransitionTailV2(ret_node);
    assert(tail);
    ret_node.transition_tail_commitment = *tail;
    graph.nodes = {ret_node};
  }

  graph.descriptor.bytecode_hash = plainHash(source.bytecode);
  graph.descriptor.bytecode_size = static_cast<uint32_t>(source.bytecode.size());
  graph.descriptor.handler_shards_size =
      static_cast<uint32_t>(raw_handlers.size());
  graph.descriptor.node_count = static_cast<uint16_t>(graph.nodes.size());
  const auto graph_hash = hashDynamicVmContinuationGraphV2(graph);
  assert(graph_hash);
  graph.descriptor.graph_commitment = *graph_hash;
  assert(validateContinuationGraphV2(abi, graph, source.bytecode,
                                     raw_handlers) ==
         DynamicVmSchemaStatusV2::Valid);

  source.continuation_descriptors = encodeDynamicVmExecutionAbiV2(abi);
  const auto encoded_graph = encodeContinuationGraphV2(graph);
  assert(!source.continuation_descriptors.empty() && !encoded_graph.empty());
  source.continuation_descriptors.insert(source.continuation_descriptors.end(),
                                         encoded_graph.begin(),
                                         encoded_graph.end());
  HandlerShardDescriptor descriptor{};
  descriptor.shard_id = graph.nodes.front().shard_id;
  descriptor.code_size = static_cast<uint32_t>(raw_handlers.size());
  descriptor.commitment = hashAarch64ShardCode(raw_handlers);
  source.handler_shards = encodeHandlerShardPayload(descriptor, raw_handlers);
  assert(!source.handler_shards.empty());
  return source;
}

void repin(EncryptedVmArtifact &artifact) {
  artifact.artifact_hash = computeEncryptedVmArtifactHash(artifact);
  assert(artifact.artifact_hash != DynamicHash{});
}

int main() {
  auto source = makeSource(true);
  auto artifact = buildEncryptedVmArtifact(source);
  assert(artifact);
  assert(artifact->encrypted_bytecode_blocks.size() >= 12);
  assert(artifact->encrypted_handler_shards.size() >= 12);
  assert(artifact->encrypted_bytecode_blocks[10] == 1);
  assert(artifact->encrypted_handler_shards[10] == 2);
  assert(artifact->encrypted_bytecode_blocks[11] == 2);
  assert(artifact->encrypted_handler_shards[11] == 2);

  const auto encoded = encodeEncryptedVmArtifact(*artifact);
  assert(!encoded.empty());
  assert(std::search(encoded.begin(), encoded.end(), source.bytecode.begin(),
                     source.bytecode.end()) == encoded.end());
  assert(std::search(encoded.begin(), encoded.end(), source.handler_shards.begin(),
                     source.handler_shards.end()) == encoded.end());
  auto source_payload = decodeHandlerShardPayload(source.handler_shards);
  assert(source_payload && !source_payload->code.empty());
  assert(std::search(encoded.begin(), encoded.end(), source_payload->code.begin(),
                     source_payload->code.end()) == encoded.end());

  auto decrypted = decryptEncryptedVmArtifact(
      *artifact, source.artifact_key, source.build_id, source.region_id,
      artifact->artifact_hash);
  assert(decrypted);
  assert(decrypted->bytecode == source.bytecode);
  assert(decrypted->handler_shards == source.handler_shards);

  const auto pinned_hash = artifact->artifact_hash;
  auto ciphertext_tamper = *artifact;
  ciphertext_tamper.encrypted_bytecode_blocks[140] ^= 1;
  repin(ciphertext_tamper);
  assert(!decryptEncryptedVmArtifact(
      ciphertext_tamper, source.artifact_key, source.build_id, source.region_id,
      ciphertext_tamper.artifact_hash));
  assert(!decryptEncryptedVmArtifact(
      ciphertext_tamper, source.artifact_key, source.build_id, source.region_id,
      pinned_hash));

  auto identity_tamper = *artifact;
  identity_tamper.encrypted_bytecode_blocks[15] ^= 1;
  repin(identity_tamper);
  assert(!decryptEncryptedVmArtifact(
      identity_tamper, source.artifact_key, source.build_id, source.region_id,
      identity_tamper.artifact_hash));

  auto commitment_tamper = *artifact;
  commitment_tamper.encrypted_handler_shards[12 + 24] ^= 1;
  repin(commitment_tamper);
  assert(!decryptEncryptedVmArtifact(
      commitment_tamper, source.artifact_key, source.build_id, source.region_id,
      commitment_tamper.artifact_hash));

  auto wrong_role = *artifact;
  wrong_role.encrypted_handler_shards = artifact->encrypted_bytecode_blocks;
  repin(wrong_role);
  assert(!decryptEncryptedVmArtifact(
      wrong_role, source.artifact_key, source.build_id, source.region_id,
      wrong_role.artifact_hash));

  constexpr size_t header = 12;
  constexpr size_t metadata = 128;
  const size_t first_record_size = metadata + 6 + 28;
  auto reordered = *artifact;
  std::vector<uint8_t> reordered_blocks(
      artifact->encrypted_bytecode_blocks.begin(),
      artifact->encrypted_bytecode_blocks.begin() + header);
  reordered_blocks.insert(reordered_blocks.end(),
      artifact->encrypted_bytecode_blocks.begin() + header + first_record_size,
      artifact->encrypted_bytecode_blocks.end());
  reordered_blocks.insert(reordered_blocks.end(),
      artifact->encrypted_bytecode_blocks.begin() + header,
      artifact->encrypted_bytecode_blocks.begin() + header + first_record_size);
  reordered.encrypted_bytecode_blocks = std::move(reordered_blocks);
  repin(reordered);
  assert(!decryptEncryptedVmArtifact(
      reordered, source.artifact_key, source.build_id, source.region_id,
      reordered.artifact_hash));

  auto duplicate = *artifact;
  duplicate.encrypted_bytecode_blocks.resize(header);
  duplicate.encrypted_bytecode_blocks.insert(
      duplicate.encrypted_bytecode_blocks.end(),
      artifact->encrypted_bytecode_blocks.begin() + header,
      artifact->encrypted_bytecode_blocks.begin() + header + first_record_size);
  duplicate.encrypted_bytecode_blocks.insert(
      duplicate.encrypted_bytecode_blocks.end(),
      artifact->encrypted_bytecode_blocks.begin() + header,
      artifact->encrypted_bytecode_blocks.begin() + header + first_record_size);
  repin(duplicate);
  assert(!decryptEncryptedVmArtifact(
      duplicate, source.artifact_key, source.build_id, source.region_id,
      duplicate.artifact_hash));

  auto missing = *artifact;
  missing.encrypted_bytecode_blocks.resize(header + first_record_size);
  missing.encrypted_bytecode_blocks[11] = 1;
  repin(missing);
  assert(!decryptEncryptedVmArtifact(
      missing, source.artifact_key, source.build_id, source.region_id,
      missing.artifact_hash));

  auto extra = *artifact;
  extra.encrypted_bytecode_blocks.push_back(0);
  repin(extra);
  assert(!decryptEncryptedVmArtifact(
      extra, source.artifact_key, source.build_id, source.region_id,
      extra.artifact_hash));

  auto descriptors_tamper = *artifact;
  descriptors_tamper.continuation_descriptors[0] ^= 1;
  repin(descriptors_tamper);
  assert(!decryptEncryptedVmArtifact(
      descriptors_tamper, source.artifact_key, source.build_id, source.region_id,
      descriptors_tamper.artifact_hash));

  auto wrong_region = source.region_id;
  wrong_region[0] ^= 1;
  assert(!decryptEncryptedVmArtifact(
      *artifact, source.artifact_key, source.build_id, wrong_region,
      artifact->artifact_hash));

  auto one_source = makeSource(false);
  auto one_artifact = buildEncryptedVmArtifact(one_source);
  assert(one_artifact);
  assert(one_artifact->encrypted_bytecode_blocks[11] == 1);
  assert(one_artifact->encrypted_handler_shards[11] == 1);
  auto one_decrypted = decryptEncryptedVmArtifact(
      *one_artifact, one_source.artifact_key, one_source.build_id,
      one_source.region_id, one_artifact->artifact_hash);
  assert(one_decrypted && one_decrypted->bytecode == one_source.bytecode &&
         one_decrypted->handler_shards == one_source.handler_shards);

  auto malformed = source;
  malformed.handler_shards = {1, 2, 3};
  assert(!buildEncryptedVmArtifact(malformed));
  auto relocated = source;
  relocated.relocation_descriptors.assign(8, 0);
  assert(!buildEncryptedVmArtifact(relocated));
  auto encoded_relocated = *artifact;
  encoded_relocated.relocation_descriptors.assign(8, 0);
  assert(encodeEncryptedVmArtifact(encoded_relocated).empty());
  auto oversized = source;
  oversized.bytecode.assign(kDynamicVmMaxWindowMaterial + 1, 1);
  assert(!buildEncryptedVmArtifact(oversized));
  auto oversized_descriptors = source;
  oversized_descriptors.continuation_descriptors.assign(
      kDynamicVmMaxDescriptor + 1, 1);
  assert(!buildEncryptedVmArtifact(oversized_descriptors));

  secureClear(*decrypted);
  assert(decrypted->bytecode.empty());
  assert(decrypted->handler_shards.empty());
  assert(decrypted->continuation_descriptors.empty());
  secureClear(*one_decrypted);
  return 0;
}
''',
        encoding="ascii",
    )
    exe = tmp_path / "probe"
    result = subprocess.run(
        [
            "c++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT),
            str(source),
            str(ROOT / "runtime/cloud_material/dynamic_vm_artifact.cpp"),
            str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
            str(ROOT / "runtime/cloud_material/dynamic_vm_shard.cpp"),
            "-lcrypto",
            "-o",
            str(exe),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
