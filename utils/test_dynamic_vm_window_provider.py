"""Focused window grant provider boundary tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_window_provider_authenticates_all_grant_metadata(tmp_path):
    source = tmp_path / "window_provider_probe.cpp"
    source.write_text(
        r'''
#include "runtime/cloud_material/dynamic_vm_window_provider.h"

#include <cassert>
#include <cstring>
#include <utility>
#include <vector>

using namespace xovm::material;

static DynamicVmWindowSelectorV3 canonicalSelector() {
  DynamicVmExecutionAbiV2 abi{};
  abi.abi_id = 0x01020304;
  abi.i32_register_count = 1;
  abi.loadi32_opcode = 0xa1;
  abi.return_i32_opcode = 0xb2;
  abi.decode_salt = 0x5a;

  DynamicVmExecutionDescriptorV2 descriptor{};
  descriptor.abi_id = abi.abi_id;
  descriptor.abi_hash = *hashDynamicVmExecutionAbiV2(abi);
  descriptor.bytecode_hash[0] = 1;
  descriptor.bytecode_size = 2;
  descriptor.handler_shards_size = 1;
  descriptor.entry_node_id = 10;
  descriptor.node_count = 1;
  descriptor.graph_commitment[0] = 2;

  ContinuationNodeV2 node{};
  node.node_id = descriptor.entry_node_id;
  node.shard_id = 20;
  node.bytecode_size = descriptor.bytecode_size;
  node.shard_size = descriptor.handler_shards_size;
  node.register_index = 0;
  node.semantic = ContinuationNodeSemanticV2::ReturnI32;
  node.status = ContinuationNodeStatusV2::Return;
  node.variant_id = 30;
  node.bytecode_block_commitment[0] = 3;
  node.handler_shard_commitment[0] = 4;
  node.transition_tail_commitment = *hashDynamicVmTransitionTailV2(node);

  auto selector = dynamicVmWindowSelectorV3(abi, descriptor, node);
  assert(selector);
  return *selector;
}

int main() {
  WindowIssueInput input{};
  input.build_id[0] = 1;
  input.region_id[0] = 2;
  input.artifact_hash[0] = 8;
  input.selector = canonicalSelector();
  input.session_id[0] = 3;
  input.session_secret[0] = 4;
  input.generation = 8;
  input.window_id = 9;
  input.now_ms = 100;
  input.expires_at_ms = 200;
  input.key_version = 5;
  input.previous_state_hash[0] = 6;
  input.next_state_hash[0] = 7;
  input.material.resize(kWindowMaterialSize);
  for (size_t index = 0; index < input.material.size(); ++index)
    input.material[index] = static_cast<uint8_t>(index);

  auto grant = issueWindowGrant(input);
  assert(grant);
  assert(grant->generation == input.generation &&
         grant->window_id == input.window_id);
  assert(grant->encrypted_window_material.size() ==
         kEncryptedWindowMaterialSize);
  assert(grant->encrypted_window_material != input.material);
  auto material = decryptWindowMaterial(*grant, input.session_secret);
  assert(material &&
         std::memcmp(&*material, input.material.data(), sizeof(*material)) == 0);
  secureClear(*material);

  const auto rejects_metadata_change = [&](auto mutate) {
    auto changed = *grant;
    mutate(changed);
    assert(!decryptWindowMaterial(changed, input.session_secret));
  };
  rejects_metadata_change([](WindowGrant &value) { ++value.format_version; });
  rejects_metadata_change([](WindowGrant &value) { value.build_id[0] ^= 1; });
  rejects_metadata_change([](WindowGrant &value) { value.region_id[0] ^= 1; });
  rejects_metadata_change([](WindowGrant &value) { value.artifact_hash[0] ^= 1; });
  rejects_metadata_change([](WindowGrant &value) { value.selector.node_id ^= 1; });
  rejects_metadata_change([](WindowGrant &value) { value.session_id[0] ^= 1; });
  rejects_metadata_change([](WindowGrant &value) { ++value.generation; });
  rejects_metadata_change([](WindowGrant &value) { ++value.window_id; });
  rejects_metadata_change(
      [](WindowGrant &value) { value.previous_state_hash[0] ^= 1; });
  rejects_metadata_change(
      [](WindowGrant &value) { value.next_state_hash[0] ^= 1; });
  rejects_metadata_change([](WindowGrant &value) { ++value.issued_at_ms; });
  rejects_metadata_change([](WindowGrant &value) { --value.expires_at_ms; });
  rejects_metadata_change([](WindowGrant &value) { ++value.key_version; });

  auto changed_nonce = *grant;
  changed_nonce.encrypted_window_material.front() ^= 1;
  assert(!decryptWindowMaterial(changed_nonce, input.session_secret));
  auto changed_ciphertext = *grant;
  changed_ciphertext.encrypted_window_material[12] ^= 1;
  assert(!decryptWindowMaterial(changed_ciphertext, input.session_secret));
  auto changed_tag = *grant;
  changed_tag.encrypted_window_material.back() ^= 1;
  assert(!decryptWindowMaterial(changed_tag, input.session_secret));
  auto short_blob = *grant;
  short_blob.encrypted_window_material.pop_back();
  assert(!decryptWindowMaterial(short_blob, input.session_secret));
  assert(encodeWindowGrant(short_blob).empty());
  auto long_blob = *grant;
  long_blob.encrypted_window_material.push_back(0);
  assert(!decryptWindowMaterial(long_blob, input.session_secret));
  assert(encodeWindowGrant(long_blob).empty());
  auto wrong_secret = input.session_secret;
  wrong_secret[0] ^= 1;
  assert(!decryptWindowMaterial(*grant, wrong_secret));
  std::array<uint8_t, 32> zero_secret{};
  assert(!decryptWindowMaterial(*grant, zero_secret));

  auto duplicate = issueWindowGrant(input);
  assert(duplicate);
  assert(duplicate->encrypted_window_material !=
         grant->encrypted_window_material);

  const auto rejects_issue = [&](auto mutate) {
    auto changed = input;
    mutate(changed);
    assert(!issueWindowGrant(changed));
  };
  rejects_issue([](WindowIssueInput &value) { value.build_id = {}; });
  rejects_issue([](WindowIssueInput &value) { value.region_id = {}; });
  rejects_issue([](WindowIssueInput &value) { value.artifact_hash = {}; });
  rejects_issue([](WindowIssueInput &value) { value.selector = {}; });
  rejects_issue([](WindowIssueInput &value) { value.session_id = {}; });
  rejects_issue([](WindowIssueInput &value) { value.session_secret = {}; });
  rejects_issue([](WindowIssueInput &value) { value.generation = 0; });
  rejects_issue([](WindowIssueInput &value) { value.window_id = 0; });
  rejects_issue(
      [](WindowIssueInput &value) { value.previous_state_hash = {}; });
  rejects_issue([](WindowIssueInput &value) { value.next_state_hash = {}; });
  rejects_issue(
      [](WindowIssueInput &value) { value.expires_at_ms = value.now_ms; });
  rejects_issue([](WindowIssueInput &value) { value.material.pop_back(); });
  rejects_issue([](WindowIssueInput &value) { value.material.push_back(0); });
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
            str(ROOT / "runtime/cloud_material/dynamic_vm_window_provider.cpp"),
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
