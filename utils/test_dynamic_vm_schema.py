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

int main() {
  using namespace xovm::material;
  static_assert(kWindowAcquireRequestEncodedSize == 130);
  static_assert(sizeof(WindowMaterial) == 192);
  static_assert(kEncryptedWindowMaterialSize == 220);

  WindowAcquireRequest request{};
  request.request_id[0] = 1;
  request.build_id[0] = 2;
  request.region_id[0] = 3;
  request.generation = 0x0102030405060708ULL;
  request.window_id = 0x1112131415161718ULL;
  request.previous_state_hash[0] = 4;
  const auto request_bytes = encodeWindowAcquireRequest(request);
  assert(request_bytes.size() == kWindowAcquireRequestEncodedSize);
  assert(request_bytes[0] == 0 && request_bytes[1] == kDynamicVmFormatVersion);
  assert(request_bytes[2] == 1 && request_bytes[18] == 2 &&
         request_bytes[50] == 3);
  assert(request_bytes[82] == 1 && request_bytes[89] == 8);
  assert(request_bytes[90] == 0x11 && request_bytes[97] == 0x18);
  assert(request_bytes[98] == 4);
  const auto decoded_request = decodeWindowAcquireRequest(request_bytes);
  assert(decoded_request && *decoded_request == request);
  assert(encodeWindowAcquireRequest(*decoded_request) == request_bytes);

  auto unsupported = request_bytes;
  unsupported[1] = static_cast<uint8_t>(kDynamicVmFormatVersion + 1);
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
  for (const auto [begin, end] : std::array<std::array<size_t, 2>, 6>{{
           {{2, 18}}, {{18, 50}}, {{50, 82}}, {{82, 90}}, {{90, 98}},
           {{98, 130}}}}) {
    auto noncanonical = request_bytes;
    std::fill(noncanonical.begin() + static_cast<std::ptrdiff_t>(begin),
              noncanonical.begin() + static_cast<std::ptrdiff_t>(end), 0);
    assert(!decodeWindowAcquireRequest(noncanonical));
  }
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
  descriptor.relocation_count = 2;
  descriptor.commitment[0] = 8;
  auto descriptor_bytes = encodeHandlerShardDescriptor(descriptor);
  assert(!descriptor_bytes.empty());
  auto decoded_descriptor = decodeHandlerShardDescriptor(descriptor_bytes);
  assert(decoded_descriptor && *decoded_descriptor == descriptor);
  descriptor_bytes.pop_back();
  assert(!decodeHandlerShardDescriptor(descriptor_bytes));

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
