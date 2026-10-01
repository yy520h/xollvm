#pragma once

#include <cstdint>
#include <string>

namespace xollvm {

struct CapabilityRequest {
  std::string protocol;
  std::string software_id;
  std::string version;
  std::string build_id;
  std::string device_id;
  std::string operation;
  std::string state;
  std::string client_nonce;
  std::string request_id;
  uint64_t client_time = 0;
  std::string code_manifest;
  std::string payload;
};

struct CapabilityResponse {
  uint32_t protocol = 0;
  bool ok = false;
  std::string operation;
  std::string request_hash;
  std::string device_id_hash;
  std::string next_state;
  std::string vm_value;
  uint64_t server_time = 0;
  uint64_t issued_at = 0;
  uint64_t expires_at = 0;
  uint32_t policy_version = 0;
  std::string key_id;
  std::string signature;
};

using CanonicalRequest = std::string;
using CanonicalResponse = std::string;

CanonicalRequest canonicalizeCapabilityRequest(const CapabilityRequest& request);
CanonicalResponse canonicalizeCapabilityResponse(const CapabilityResponse& response);
bool parseCapabilityRequest(const std::string& canonical, CapabilityRequest* out);
bool parseCapabilityResponse(const std::string& canonical, CapabilityResponse* out);
bool validateCapabilityRequest(const CapabilityRequest& request);
bool validateCapabilityResponse(const CapabilityResponse& response);

}  // namespace xollvm
