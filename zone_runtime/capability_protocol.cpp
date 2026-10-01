#include "capability_protocol.h"

#include <charconv>
#include <cctype>
#include <limits>
#include <sstream>
#include <utility>
#include <vector>

namespace xollvm {
namespace {

struct Field {
  const char* name;
  std::string value;
};

std::string encodeFields(const std::vector<Field>& fields) {
  std::string result;
  for (const Field& field : fields) {
    result.append(field.name);
    result.push_back(':');
    result.append(std::to_string(field.value.size()));
    result.push_back(':');
    result.append(field.value);
    result.push_back('\n');
  }
  return result;
}

bool parseUnsigned(const std::string& value, uint64_t* out) {
  if (value.empty()) {
    return false;
  }
  uint64_t parsed = 0;
  const char* begin = value.data();
  const char* end = begin + value.size();
  auto result = std::from_chars(begin, end, parsed, 10);
  if (result.ec != std::errc() || result.ptr != end) {
    return false;
  }
  *out = parsed;
  return true;
}

bool parseFields(const std::string& input, const std::vector<const char*>& names,
                 std::vector<std::string>* values) {
  size_t offset = 0;
  values->clear();
  for (const char* expected_name : names) {
    size_t name_end = input.find(':', offset);
    if (name_end == std::string::npos ||
        input.compare(offset, name_end - offset, expected_name) != 0) {
      return false;
    }
    size_t length_end = input.find(':', name_end + 1);
    if (length_end == std::string::npos) {
      return false;
    }
    uint64_t length = 0;
    if (!parseUnsigned(input.substr(name_end + 1, length_end - name_end - 1),
                       &length) ||
        length > std::numeric_limits<size_t>::max()) {
      return false;
    }
    size_t value_start = length_end + 1;
    size_t value_length = static_cast<size_t>(length);
    if (value_length > input.size() - value_start) {
      return false;
    }
    values->push_back(input.substr(value_start, value_length));
    offset = value_start + value_length;
    if (offset >= input.size() || input[offset] != '\n') {
      return false;
    }
    ++offset;
  }
  return offset == input.size();
}

bool isHexAtLeast128(const std::string& value) {
  if (value.size() < 32 || value.size() % 2 != 0) {
    return false;
  }
  for (unsigned char byte : value) {
    if (!std::isxdigit(byte)) {
      return false;
    }
  }
  return true;
}

bool nonEmpty(const std::string& value) { return !value.empty(); }

}  // namespace

CanonicalRequest canonicalizeCapabilityRequest(const CapabilityRequest& request) {
  return encodeFields({
      {"protocol", request.protocol},
      {"software_id", request.software_id},
      {"version", request.version},
      {"build_id", request.build_id},
      {"device_id", request.device_id},
      {"operation", request.operation},
      {"state", request.state},
      {"client_nonce", request.client_nonce},
      {"request_id", request.request_id},
      {"client_time", std::to_string(request.client_time)},
      {"code_manifest", request.code_manifest},
      {"payload", request.payload},
  });
}

CanonicalResponse canonicalizeCapabilityResponse(const CapabilityResponse& response) {
  return encodeFields({
      {"protocol", std::to_string(response.protocol)},
      {"ok", response.ok ? "true" : "false"},
      {"operation", response.operation},
      {"request_hash", response.request_hash},
      {"device_id_hash", response.device_id_hash},
      {"next_state", response.next_state},
      {"vm_value", response.vm_value},
      {"server_time", std::to_string(response.server_time)},
      {"issued_at", std::to_string(response.issued_at)},
      {"expires_at", std::to_string(response.expires_at)},
      {"policy_version", std::to_string(response.policy_version)},
      {"key_id", response.key_id},
  });
}

bool validateCapabilityRequest(const CapabilityRequest& request) {
  return request.protocol == "capability_v1" && nonEmpty(request.software_id) &&
         nonEmpty(request.version) && nonEmpty(request.build_id) &&
         nonEmpty(request.device_id) && nonEmpty(request.operation) &&
         isHexAtLeast128(request.state) && isHexAtLeast128(request.client_nonce) &&
         isHexAtLeast128(request.request_id) && nonEmpty(request.code_manifest);
}

bool validateCapabilityResponse(const CapabilityResponse& response) {
  return response.protocol == 1 && response.ok && nonEmpty(response.operation) &&
         isHexAtLeast128(response.request_hash) &&
         isHexAtLeast128(response.device_id_hash) &&
         nonEmpty(response.next_state) && nonEmpty(response.vm_value) &&
         response.issued_at <= response.expires_at && nonEmpty(response.key_id);
}

bool parseCapabilityRequest(const std::string& canonical, CapabilityRequest* out) {
  if (out == nullptr) {
    return false;
  }
  std::vector<std::string> values;
  if (!parseFields(canonical,
                   {"protocol", "software_id", "version", "build_id", "device_id",
                    "operation", "state", "client_nonce", "request_id", "client_time",
                    "code_manifest", "payload"},
                   &values)) {
    return false;
  }
  uint64_t client_time = 0;
  if (!parseUnsigned(values[9], &client_time)) {
    return false;
  }
  CapabilityRequest parsed{values[0], values[1], values[2], values[3], values[4],
                           values[5], values[6], values[7], values[8], client_time,
                           values[10], values[11]};
  if (!validateCapabilityRequest(parsed)) {
    return false;
  }
  *out = std::move(parsed);
  return true;
}

bool parseCapabilityResponse(const std::string& canonical, CapabilityResponse* out) {
  if (out == nullptr) {
    return false;
  }
  std::vector<std::string> values;
  if (!parseFields(canonical,
                   {"protocol", "ok", "operation", "request_hash", "device_id_hash",
                    "next_state", "vm_value", "server_time", "issued_at", "expires_at",
                    "policy_version", "key_id"},
                   &values)) {
    return false;
  }
  uint64_t protocol = 0;
  uint64_t server_time = 0;
  uint64_t issued_at = 0;
  uint64_t expires_at = 0;
  uint64_t policy_version = 0;
  if (!parseUnsigned(values[0], &protocol) || !parseUnsigned(values[7], &server_time) ||
      !parseUnsigned(values[8], &issued_at) || !parseUnsigned(values[9], &expires_at) ||
      !parseUnsigned(values[10], &policy_version) ||
      (values[1] != "true" && values[1] != "false") || protocol > UINT32_MAX ||
      policy_version > UINT32_MAX) {
    return false;
  }
  CapabilityResponse parsed{static_cast<uint32_t>(protocol), values[1] == "true", values[2],
                            values[3], values[4], values[5], values[6], server_time,
                            issued_at, expires_at, static_cast<uint32_t>(policy_version),
                            values[11], {}};
  if (!validateCapabilityResponse(parsed)) {
    return false;
  }
  *out = std::move(parsed);
  return true;
}

}  // namespace xollvm
