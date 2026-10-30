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

ArtifactSourceV3 makeSource(bool two_nodes) {
  ArtifactSourceV3 source{};
  source.build_id[0] = 1;
  source.region_id[0] = 2;

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
  for (const auto &node : graph.nodes) {
    DynamicVmNodeCapabilityV3 capability{};
    capability.node_id = node.node_id;
    capability.capability.fill(static_cast<uint8_t>(0x30 + node.node_id));
    source.node_capabilities.push_back(capability);
  }
  return source;
}

void repin(EncryptedVmArtifact &artifact) {
  artifact.artifact_hash = computeEncryptedVmArtifactHash(artifact);
  assert(artifact.artifact_hash != DynamicHash{});
}

int main() {
  auto source = makeSource(true);
  auto built = buildSelectiveEncryptedVmArtifactV3(source);
  assert(built);
  auto &artifact = built->artifact;
  assert(artifact.format_version == kDynamicVmSelectiveFormatVersionV3);
  assert(artifact.encrypted_bytecode_blocks.size() >= 12);
  assert(artifact.encrypted_handler_shards.size() >= 12);
  assert(artifact.encrypted_bytecode_blocks[10] == 1);
  assert(artifact.encrypted_handler_shards[10] == 2);
  assert(artifact.encrypted_bytecode_blocks[11] == 2);
  assert(artifact.encrypted_handler_shards[11] == 2);

  const auto encoded = encodeEncryptedVmArtifact(artifact);
  assert(!encoded.empty());
  assert(std::search(encoded.begin(), encoded.end(), source.bytecode.begin(),
                     source.bytecode.end()) == encoded.end());
  auto source_payload = decodeHandlerShardPayload(source.handler_shards);
  assert(source_payload && !source_payload->code.empty());
  assert(std::search(encoded.begin(), encoded.end(), source_payload->code.begin(),
                     source_payload->code.end()) == encoded.end());

  const auto descriptors = std::span<const uint8_t>(artifact.continuation_descriptors);
  auto parsed_abi = decodeDynamicVmExecutionAbiV2(
      descriptors.first(kDynamicVmExecutionAbiV2EncodedSize));
  auto parsed_graph = decodeContinuationGraphV2(
      descriptors.subspan(kDynamicVmExecutionAbiV2EncodedSize));
  assert(parsed_abi && parsed_graph && parsed_graph->nodes.size() == 2);
  auto selector0 = dynamicVmWindowSelectorV3(
      *parsed_abi, parsed_graph->descriptor, parsed_graph->nodes[0]);
  auto selector1 = dynamicVmWindowSelectorV3(
      *parsed_abi, parsed_graph->descriptor, parsed_graph->nodes[1]);
  assert(selector0 && selector1);
  auto capability0 = built->registration.capabilityFor(*selector0);
  auto capability1 = built->registration.capabilityFor(*selector1);
  assert(capability0 && capability1 && *capability0 != *capability1);
  auto node0 = decryptSelectiveDynamicVmNodeV3(
      artifact, *selector0, *capability0, source.build_id, source.region_id,
      artifact.artifact_hash);
  assert(node0 && node0->node().node_id == selector0->node_id);
  assert(node0->bytecodeBlock().size() == selector0->bytecode_size);
  assert(node0->handlerShard().size() == selector0->shard_size);
  assert(!decryptSelectiveDynamicVmNodeV3(
      artifact, *selector1, *capability0, source.build_id, source.region_id,
      artifact.artifact_hash));
  assert(!decryptSelectiveDynamicVmNodeV3(
      artifact, *selector0, *capability1, source.build_id, source.region_id,
      artifact.artifact_hash));

  auto bad_selector = *selector0;
  bad_selector.variant_id += 1;
  assert(!decryptSelectiveDynamicVmNodeV3(
      artifact, bad_selector, *capability0, source.build_id, source.region_id,
      artifact.artifact_hash));
  auto tampered = artifact;
  tampered.encrypted_bytecode_blocks[12 + 128 + 12] ^= 1;
  repin(tampered);
  assert(!decryptSelectiveDynamicVmNodeV3(
      tampered, *selector0, *capability0, source.build_id, source.region_id,
      tampered.artifact_hash));
  auto wrong_region = source.region_id;
  wrong_region[0] ^= 1;
  assert(!decryptSelectiveDynamicVmNodeV3(
      artifact, *selector0, *capability0, source.build_id, wrong_region,
      artifact.artifact_hash));

  auto one_source = makeSource(false);
  auto one_built = buildSelectiveEncryptedVmArtifactV3(one_source);
  assert(one_built);
  assert(one_built->artifact.encrypted_bytecode_blocks[11] == 1);
  assert(one_built->artifact.encrypted_handler_shards[11] == 1);

  auto malformed = source;
  malformed.handler_shards = {1, 2, 3};
  assert(!buildSelectiveEncryptedVmArtifactV3(malformed));
  auto duplicate_capability = source;
  duplicate_capability.node_capabilities[1].capability =
      duplicate_capability.node_capabilities[0].capability;
  assert(!buildSelectiveEncryptedVmArtifactV3(duplicate_capability));
  auto relocated = source;
  relocated.relocation_descriptors.assign(8, 0);
  assert(!buildSelectiveEncryptedVmArtifactV3(relocated));
  auto encoded_relocated = artifact;
  encoded_relocated.relocation_descriptors.assign(8, 0);
  assert(encodeEncryptedVmArtifact(encoded_relocated).empty());
  auto oversized = source;
  oversized.bytecode.assign(kDynamicVmMaxWindowMaterial + 1, 1);
  assert(!buildSelectiveEncryptedVmArtifactV3(oversized));

  node0->clear();
  assert(node0->bytecodeBlock().empty());
  assert(node0->handlerShard().empty());
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
