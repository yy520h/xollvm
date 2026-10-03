#pragma once

#include "capability_protocol.h"

#include <cstdint>
#include <string>

namespace xollvm {

struct CapabilityClientConfig {
  std::string operation;
  std::string build_manifest;
  std::string public_key_pem;
  std::string key_id = "key-1";
  std::string state_path;
  uint32_t policy_version = 1;
  uint64_t server_time = 0;
  uint64_t clock_skew_seconds = 30;
};

class CapabilityClient {
 public:
  explicit CapabilityClient(CapabilityClientConfig config);

  bool acceptResponse(const CapabilityResponse& response,
                      const std::string& expected_request_hash,
                      const std::string& expected_device_id_hash = "");
  // 修复 #7：vm_dispatch 响应的校验入口 — 复用验签/绑定校验，
  // 但不 writeState（vm_dispatch 的 next_state 不应覆盖 capability state）。
  bool verifyDispatchResponse(const CapabilityResponse& response,
                              const std::string& expected_request_hash,
                              const std::string& expected_device_id_hash = "") const;
  bool hasState() const;
  const std::string& state() const;
  const CapabilityResponse& response() const;
  bool require(const std::string& operation, uint64_t now) const;

  // Test-only key generation keeps private material out of production config.
  bool signTestResponse(CapabilityResponse* response);

 private:
  bool verifySignature(const CapabilityResponse& response) const;
  bool writeState(const CapabilityResponse& response);
  bool loadState();

  CapabilityClientConfig config_;
  std::string state_;
  CapabilityResponse response_;
};

}  // namespace xollvm
