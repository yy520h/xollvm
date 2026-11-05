"""Focused tests for the dynamic VM canonical schema."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_dynamic_vm_schema_probe(tmp_path):
    source = tmp_path / "dynamic_vm_probe.cpp"
    source.write_text(
        r'''
#include "runtime/cloud_material/dynamic_vm_schema.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <openssl/evp.h>

int main() {
  using namespace xovm::material;
  static_assert(kWindowAcquireRequestEncodedSize == 374);
  static_assert(sizeof(WindowMaterial) == 192);
  static_assert(kEncryptedWindowMaterialSize == 220);
  static_assert(kDynamicVmExecutionAbiV2EncodedSize == 66);
  static_assert(kDynamicVmExecutionDescriptorV2EncodedSize == 120);
  static_assert(kDynamicVmContinuationNodeV2EncodedSize == 140);

  DynamicVmExecutionAbiV2 abi{};
  abi.abi_id = 0x01020304;
  abi.i32_register_count = 2;
  abi.loadi32_opcode = 0xa1;
  abi.return_i32_opcode = 0xb2;
  abi.decode_salt = 0x5a;
  assert(validateDynamicVmExecutionAbiV2(abi) == DynamicVmSchemaStatusV2::Valid);
  const auto abi_bytes = encodeDynamicVmExecutionAbiV2(abi);
  assert(abi_bytes.size() == kDynamicVmExecutionAbiV2EncodedSize);
  assert(abi_bytes[0] == 0 && abi_bytes[1] == kDynamicVmFormatVersion);
  assert(abi_bytes[4] == 0 && abi_bytes[5] == 1);
  assert(abi_bytes[8] == 1 && abi_bytes[11] == 4);
  assert(abi_bytes[12] == 0 && abi_bytes[13] == 2);
  assert(abi_bytes[22] == 0 && abi_bytes[23] == 6);
  assert(abi_bytes[24] == 0 && abi_bytes[25] == 2);
  assert(abi_bytes[26] == 0xa1 && abi_bytes[27] == 0xb2);
  assert(abi_bytes[28] == 1 && abi_bytes[29] == 2 && abi_bytes[30] == 1);
  assert(abi_bytes[32] == 0x5a);
  const auto decoded_abi = decodeDynamicVmExecutionAbiV2(abi_bytes);
  assert(decoded_abi && *decoded_abi == abi);
  const auto abi_hash = hashDynamicVmExecutionAbiV2(abi);
  assert(abi_hash && *abi_hash != DynamicHash{});
  auto bad_abi = abi_bytes;
  bad_abi[20] = 0;
  bad_abi[21] = 1;
  assert(!decodeDynamicVmExecutionAbiV2(bad_abi));
  bad_abi = abi_bytes;
  bad_abi.push_back(0);
  assert(!decodeDynamicVmExecutionAbiV2(bad_abi));
  auto invalid_abi = abi;
  invalid_abi.i64_register_count = 1;
  assert(encodeDynamicVmExecutionAbiV2(invalid_abi).empty());
  invalid_abi = abi;
  invalid_abi.i32_register_count = 251;
  assert(validateDynamicVmExecutionAbiV2(invalid_abi) ==
         DynamicVmSchemaStatusV2::InvalidRegisterCounts);
  invalid_abi = abi;
  invalid_abi.reserved_decode_salt[0] = 1;
  assert(validateDynamicVmExecutionAbiV2(invalid_abi) ==
         DynamicVmSchemaStatusV2::InvalidIdentity);
  invalid_abi = abi;
  invalid_abi.loadi32_immediate_offset = 3;
  assert(validateDynamicVmExecutionAbiV2(invalid_abi) ==
         DynamicVmSchemaStatusV2::InvalidInstructionBoundary);
  invalid_abi = abi;
  invalid_abi.return_i32_opcode = invalid_abi.loadi32_opcode;
  assert(validateDynamicVmExecutionAbiV2(invalid_abi) ==
         DynamicVmSchemaStatusV2::InvalidInstructionBoundary);

  std::vector<uint8_t> bytecode = {0xa1, static_cast<uint8_t>(0x01 ^ abi.decode_salt),
                                   0x11, 0x22, 0x33, 0x44, 0xb2,
                                   static_cast<uint8_t>(0x01 ^ abi.decode_salt)};
  std::vector<uint8_t> shards = {1, 2, 3, 4, 5};
  DynamicHash bytecode_hash{};
  unsigned int digest_size = 0;
  assert(EVP_Digest(bytecode.data(), bytecode.size(), bytecode_hash.data(),
                    &digest_size, EVP_sha256(), nullptr) == 1);
  assert(digest_size == bytecode_hash.size());
  ContinuationGraphV2 graph{};
  graph.descriptor.abi_id = abi.abi_id;
  graph.descriptor.abi_hash = *abi_hash;
  graph.descriptor.bytecode_hash = bytecode_hash;
  graph.descriptor.bytecode_size = bytecode.size();
  graph.descriptor.handler_shards_size = shards.size();
  graph.descriptor.entry_node_id = 10;
  graph.descriptor.node_count = 2;
  ContinuationNodeV2 load{};
  load.node_id = 10;
  load.shard_id = 20;
  load.bytecode_size = 6;
  load.shard_size = 2;
  load.next_node_id = 11;
  load.register_index = 1;
  load.semantic = ContinuationNodeSemanticV2::LoadI32;
  load.status = ContinuationNodeStatusV2::Continue;
  load.variant_id = 100;
  load.bytecode_block_commitment =
      hashDynamicVmBytecodeBlockV2(std::span<const uint8_t>(bytecode).first(6));
  load.handler_shard_commitment =
      hashDynamicVmHandlerShardV2(std::span<const uint8_t>(shards).first(2));
  ContinuationNodeV2 ret{};
  ret.node_id = 11;
  ret.shard_id = 21;
  ret.bytecode_offset = 6;
  ret.bytecode_size = 2;
  ret.shard_offset = 2;
  ret.shard_size = 3;
  ret.register_index = 1;
  ret.semantic = ContinuationNodeSemanticV2::ReturnI32;
  ret.status = ContinuationNodeStatusV2::Return;
  ret.variant_id = 101;
  ret.bytecode_block_commitment =
      hashDynamicVmBytecodeBlockV2(std::span<const uint8_t>(bytecode).last(2));
  ret.handler_shard_commitment =
      hashDynamicVmHandlerShardV2(std::span<const uint8_t>(shards).last(3));
  load.transition_tail_commitment = *hashDynamicVmTransitionTailV2(load);
  ret.transition_tail_commitment = *hashDynamicVmTransitionTailV2(ret);
  graph.nodes = {load, ret};
  graph.descriptor.graph_commitment = *hashDynamicVmContinuationGraphV2(graph);
  assert(validateContinuationGraphV2(abi, graph) ==
         DynamicVmSchemaStatusV2::Valid);
  assert(validateContinuationGraphV2(abi, graph, bytecode, shards) ==
         DynamicVmSchemaStatusV2::Valid);
  auto graph_bytes = encodeContinuationGraphV2(graph);
  assert(graph_bytes.size() == 120 + 2 * 140);
  auto decoded_graph = decodeContinuationGraphV2(graph_bytes);
  assert(decoded_graph && *decoded_graph == graph);
  assert(encodeContinuationGraphV2(*decoded_graph) == graph_bytes);
  graph_bytes.push_back(0);
  assert(!decodeContinuationGraphV2(graph_bytes));
  auto noncanonical_graph_bytes = encodeContinuationGraphV2(graph);
  noncanonical_graph_bytes[120 + 4 + 3] = 0;
  assert(!decodeContinuationGraphV2(noncanonical_graph_bytes));

  auto bad_graph = graph;
  bad_graph.nodes[1].node_id = 10;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidIdOrder);
  bad_graph = graph;
  bad_graph.nodes[0].next_node_id = 0;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidTopology);
  bad_graph = graph;
  bad_graph.nodes[1].bytecode_offset = 5;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidInstructionBoundary);
  bad_graph = graph;
  bad_graph.nodes[0].register_index = 2;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidRegisterCounts);
  bad_graph = graph;
  bad_graph.nodes[0].relocation_count = 1;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidRelocation);
  bad_graph = graph;
  bad_graph.descriptor.abi_hash[0] ^= 1;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidHashBinding);
  bad_graph = graph;
  bad_graph.nodes[1].semantic = ContinuationNodeSemanticV2::LoadI32;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidSemantic);
  bad_graph = graph;
  bad_graph.nodes[0].variant_id = 0;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidIdentity);
  bad_graph = graph;
  bad_graph.nodes[0].handler_shard_commitment[0] ^= 1;
  assert(validateContinuationGraphV2(abi, bad_graph, bytecode, shards) ==
         DynamicVmSchemaStatusV2::InvalidHashBinding);
  bad_graph = graph;
  bad_graph.nodes[0].transition_tail_commitment[0] ^= 1;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidHashBinding);
  bad_graph = graph;
  bad_graph.descriptor.graph_commitment[0] ^= 1;
  assert(validateContinuationGraphV2(abi, bad_graph) ==
         DynamicVmSchemaStatusV2::InvalidHashBinding);
  auto bad_bytecode = bytecode;
  bad_bytecode[0] ^= 1;
  assert(validateContinuationGraphV2(abi, graph, bad_bytecode, shards) ==
         DynamicVmSchemaStatusV2::InvalidHashBinding);
  bad_bytecode = bytecode;
  bad_bytecode[7] = 0;
  DynamicHash bad_hash{};
  assert(EVP_Digest(bad_bytecode.data(), bad_bytecode.size(), bad_hash.data(),
                    &digest_size, EVP_sha256(), nullptr) == 1);
  bad_graph = graph;
  bad_graph.descriptor.bytecode_hash = bad_hash;
  bad_graph.nodes[1].bytecode_block_commitment =
      hashDynamicVmBytecodeBlockV2(std::span<const uint8_t>(bad_bytecode).last(2));
  bad_graph.nodes[1].transition_tail_commitment =
      *hashDynamicVmTransitionTailV2(bad_graph.nodes[1]);
  bad_graph.descriptor.graph_commitment =
      *hashDynamicVmContinuationGraphV2(bad_graph);
  assert(validateContinuationGraphV2(abi, bad_graph, bad_bytecode, shards) ==
         DynamicVmSchemaStatusV2::InvalidRegisterCounts);

  ContinuationGraphV2 one_node = graph;
  one_node.descriptor.bytecode_hash = {};
  std::vector<uint8_t> ret_only = {
      0xb2, static_cast<uint8_t>(0x01 ^ abi.decode_salt)};
  assert(EVP_Digest(ret_only.data(), ret_only.size(),
                    one_node.descriptor.bytecode_hash.data(), &digest_size,
                    EVP_sha256(), nullptr) == 1);
  one_node.descriptor.bytecode_size = ret_only.size();
  one_node.descriptor.handler_shards_size = 3;
  one_node.descriptor.entry_node_id = 11;
  one_node.descriptor.node_count = 1;
  one_node.nodes = {graph.nodes[1]};
  one_node.nodes[0].bytecode_offset = 0;
  one_node.nodes[0].shard_offset = 0;
  one_node.nodes[0].bytecode_block_commitment =
      hashDynamicVmBytecodeBlockV2(ret_only);
  one_node.nodes[0].handler_shard_commitment =
      hashDynamicVmHandlerShardV2(std::span<const uint8_t>(shards).last(3));
  one_node.nodes[0].transition_tail_commitment =
      *hashDynamicVmTransitionTailV2(one_node.nodes[0]);
  one_node.descriptor.graph_commitment =
      *hashDynamicVmContinuationGraphV2(one_node);
  assert(validateContinuationGraphV2(abi, one_node, ret_only,
                                     std::span<const uint8_t>(shards).last(3)) ==
         DynamicVmSchemaStatusV2::Valid);

  WindowAcquireRequest request{};
  request.request_id[0] = 1;
  request.build_id[0] = 2;
  request.region_id[0] = 3;
  request.generation = 0x0102030405060708ULL;
  request.window_id = 0x1112131415161718ULL;
  request.previous_state_hash[0] = 4;
  request.artifact_hash[0] = 5;
  request.selector = *dynamicVmWindowSelectorV3(abi, graph.descriptor, graph.nodes[0]);
  const auto request_bytes = encodeWindowAcquireRequest(request);
  assert(request_bytes.size() == kWindowAcquireRequestEncodedSize);
  assert(request_bytes[0] == 0 && request_bytes[1] == kDynamicVmSelectiveFormatVersionV3);
  assert(request_bytes[2] == 1 && request_bytes[18] == 2 &&
         request_bytes[50] == 3 && request_bytes[82] == 5);
  const auto decoded_request = decodeWindowAcquireRequest(request_bytes);
  assert(decoded_request && *decoded_request == request);
  assert(encodeWindowAcquireRequest(*decoded_request) == request_bytes);
  auto invalid_selector = request.selector;
  invalid_selector.status = ContinuationNodeStatusV2::Return;
  assert(!validateDynamicVmWindowSelectorV3(invalid_selector));
  assert(encodeDynamicVmWindowSelectorV3(invalid_selector).empty());
  invalid_selector = request.selector;
  invalid_selector.semantic = ContinuationNodeSemanticV2::ReturnI32;
  assert(!validateDynamicVmWindowSelectorV3(invalid_selector));
  invalid_selector = request.selector;
  invalid_selector.next_node_id = 0;
  assert(!validateDynamicVmWindowSelectorV3(invalid_selector));
  invalid_selector = request.selector;
  invalid_selector.bytecode_offset = UINT32_MAX;
  assert(!validateDynamicVmWindowSelectorV3(invalid_selector));
  invalid_selector = request.selector;
  invalid_selector.shard_offset = UINT32_MAX;
  assert(!validateDynamicVmWindowSelectorV3(invalid_selector));
  auto terminal_selector = *dynamicVmWindowSelectorV3(
      abi, graph.descriptor, graph.nodes[1]);
  terminal_selector.status = ContinuationNodeStatusV2::Continue;
  assert(!validateDynamicVmWindowSelectorV3(terminal_selector));
  terminal_selector = *dynamicVmWindowSelectorV3(
      abi, graph.descriptor, graph.nodes[1]);
  terminal_selector.next_node_id = graph.nodes[0].node_id;
  assert(!validateDynamicVmWindowSelectorV3(terminal_selector));

  auto unsupported = request_bytes;
  unsupported[1] = static_cast<uint8_t>(kDynamicVmSelectiveFormatVersionV3 + 1);
  assert(!decodeWindowAcquireRequest(unsupported));
  auto zero_version = request_bytes;
  zero_version[0] = zero_version[1] = 0;
  assert(!decodeWindowAcquireRequest(zero_version));
  auto truncated = request_bytes;
  truncated.pop_back();
  assert(!decodeWindowAcquireRequest(truncated));
  auto trailing = request_bytes;
  trailing.push_back(0);
  assert(!decodeWindowAcquireRequest(trailing));
  auto invalid_request = request;
  invalid_request.request_id = {};
  assert(encodeWindowAcquireRequest(invalid_request).empty());
  invalid_request = request;
  invalid_request.generation = 0;
  assert(encodeWindowAcquireRequest(invalid_request).empty());

  WindowGrant grant{};
  grant.issued_at_ms = 100;
  grant.expires_at_ms = 200;
  grant.generation = 3;
  grant.window_id = 4;
  grant.next_state_hash[0] = 9;
  grant.artifact_hash = request.artifact_hash;
  grant.selector = request.selector;
  grant.build_id[0] = 1;
  grant.region_id[0] = 2;
  grant.session_id[0] = 3;
  grant.previous_state_hash[0] = 4;
  grant.encrypted_window_material.assign(kEncryptedWindowMaterialSize, 1);
  auto grant_bytes = encodeWindowGrant(grant);
  assert(!grant_bytes.empty());
  auto invalid_grant = grant;
  invalid_grant.generation = 0;
  assert(encodeWindowGrant(invalid_grant).empty());
  invalid_grant = grant;
  invalid_grant.encrypted_window_material.pop_back();
  assert(encodeWindowGrant(invalid_grant).empty());
  invalid_grant = grant;
  invalid_grant.encrypted_window_material.push_back(0);
  assert(encodeWindowGrant(invalid_grant).empty());
  auto decoded_grant = decodeWindowGrant(grant_bytes);
  assert(decoded_grant && decoded_grant->generation == grant.generation &&
         decoded_grant->encrypted_window_material ==
             grant.encrypted_window_material);
  grant_bytes.push_back(0);
  assert(!decodeWindowGrant(grant_bytes));
  grant_bytes = encodeWindowGrant(grant);
  grant_bytes.resize(3);
  assert(!decodeWindowGrant(grant_bytes));

  WindowBinding binding{};
  binding.build_id = grant.build_id;
  binding.region_id = grant.region_id;
  binding.artifact_hash = grant.artifact_hash;
  binding.selector = grant.selector;
  binding.session_id = grant.session_id;
  binding.now_ms = 150;
  binding.generation = 3;
  binding.window_id = 4;
  binding.previous_state_hash = grant.previous_state_hash;
  assert(validateWindowBinding(grant, binding));
  binding.window_id = 5;
  assert(!validateWindowBinding(grant, binding));
  DynamicHash next{};
  assert(advanceContinuation(grant.previous_state_hash, grant, next));
  assert(next == grant.next_state_hash);

  HandlerShardDescriptor descriptor{};
  descriptor.shard_id = 7;
  descriptor.code_size = 32;
  descriptor.relocation_count = 0;
  descriptor.commitment[0] = 8;
  auto descriptor_bytes = encodeHandlerShardDescriptor(descriptor);
  assert(!descriptor_bytes.empty());
  auto decoded_descriptor = decodeHandlerShardDescriptor(descriptor_bytes);
  assert(decoded_descriptor && *decoded_descriptor == descriptor);
  descriptor_bytes.pop_back();
  assert(!decodeHandlerShardDescriptor(descriptor_bytes));
  descriptor.relocation_count = 1;
  assert(encodeHandlerShardDescriptor(descriptor).empty());

  std::array<unsigned char, 32> secret{};
  secret[0] = 7;
  auto material = deriveWindowMaterial(secret, grant);
  assert(material.window != material.permutation);
  secureClear(material);
  for (auto byte : material.window) assert(byte == 0);
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
            str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
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
