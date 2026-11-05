#include <cassert>
#include <cstdint>

#include "runtime/cloud_material/raw_socket_cloud_provider.h"

namespace xovm::material::test {

bool testConnectionConfigValidation() {
  xovm::material::RawSocketCloudProvider::ConnectionConfig config;
  config.remote_ip = 0x7F000001;  // 127.0.0.1
  config.remote_port = 8080;
  config.connection_timeout = 5000;
  config.max_retries = 3;
  config.buffer_size = 65536;

  // Valid config should work
  auto provider = xovm::material::RawSocketCloudProvider::create(config);
  // Note: create may fail due to no server, but validation should pass

  // Invalid: zero port
  config.remote_port = 0;
  provider = xovm::material::RawSocketCloudProvider::create(config);
  assert(!provider.has_value() && "Should reject zero port");

  // Invalid: timeout too large
  config.remote_port = 8080;
  config.connection_timeout = 61000;
  provider = xovm::material::RawSocketCloudProvider::create(config);
  assert(!provider.has_value() && "Should reject timeout > 60000");

  // Invalid: max_retries too large
  config.connection_timeout = 5000;
  config.max_retries = 11;
  provider = xovm::material::RawSocketCloudProvider::create(config);
  assert(!provider.has_value() && "Should reject max_retries > 10");

  // Invalid: buffer_size too large
  config.max_retries = 3;
  config.buffer_size = 2000000;
  provider = xovm::material::RawSocketCloudProvider::create(config);
  assert(!provider.has_value() && "Should reject buffer_size > 1MB");

  return true;
}

bool testMessageHeaderConstruction() {
  std::vector<uint8_t> payload = {1, 2, 3, 4, 5};

  // Test header magic
  auto header =
      xovm::material::RawSocketCloudProvider::MessageHeader{};
  header.magic = xovm::material::RawSocketCloudProvider::kWireProtocolMagic;
  assert(header.magic == 0xDEADBEEF);

  // Test max payload size
  assert(xovm::material::RawSocketCloudProvider::kMaxPayloadSize == 65536);

  return true;
}

bool testChecksumComputation() {
  std::vector<uint8_t> data1 = {1, 2, 3, 4, 5};
  std::vector<uint8_t> data2 = {1, 2, 3, 4, 5};
  std::vector<uint8_t> data3 = {1, 2, 3, 4, 6};

  // Same data should have same checksum
  uint32_t checksum1 =
      xovm::material::RawSocketCloudProvider::computeChecksum(data1);
  uint32_t checksum2 =
      xovm::material::RawSocketCloudProvider::computeChecksum(data2);
  assert(checksum1 == checksum2);

  // Different data should have different checksum
  uint32_t checksum3 =
      xovm::material::RawSocketCloudProvider::computeChecksum(data3);
  assert(checksum1 != checksum3);

  return true;
}

bool testChecksumValidation() {
  std::vector<uint8_t> data = {10, 20, 30, 40, 50};
  uint32_t correct_checksum =
      xovm::material::RawSocketCloudProvider::computeChecksum(data);

  // Validation should pass with correct checksum
  assert(xovm::material::RawSocketCloudProvider::validateChecksum(
      data, correct_checksum));

  // Validation should fail with incorrect checksum
  assert(!xovm::material::RawSocketCloudProvider::validateChecksum(data,
                                                                    0xDEADBEEF));

  return true;
}

bool testHeaderParsing() {
  // Create a valid header
  std::vector<uint8_t> payload = {100, 200, 100, 200};
  std::vector<uint8_t> header_data;

  xovm::material::RawSocketCloudProvider::MessageHeader header;
  header.magic = xovm::material::RawSocketCloudProvider::kWireProtocolMagic;
  header.message_id = 42;
  header.payload_size = payload.size();
  header.checksum =
      xovm::material::RawSocketCloudProvider::computeChecksum(payload);

  // Serialize header
  uint8_t* header_ptr = (uint8_t*)&header;
  header_data.insert(header_data.end(), header_ptr,
                     header_ptr + sizeof(header));

  // Parse it back
  auto parsed = xovm::material::RawSocketCloudProvider::parseHeader(header_data);
  assert(parsed.has_value() && "Should parse valid header");
  assert(parsed->magic ==
         xovm::material::RawSocketCloudProvider::kWireProtocolMagic);
  assert(parsed->message_id == 42);
  assert(parsed->payload_size == payload.size());

  return true;
}

bool testHeaderParsingInvalid() {
  // Test with invalid magic
  std::vector<uint8_t> bad_header;
  xovm::material::RawSocketCloudProvider::MessageHeader header;
  header.magic = 0xBADBADBA;  // wrong magic
  header.message_id = 42;
  header.payload_size = 100;
  header.checksum = 0;

  uint8_t* header_ptr = (uint8_t*)&header;
  bad_header.insert(bad_header.end(), header_ptr,
                    header_ptr + sizeof(header));

  auto parsed = xovm::material::RawSocketCloudProvider::parseHeader(bad_header);
  assert(!parsed.has_value() && "Should reject invalid magic");

  // Test with payload size too large
  header.magic = xovm::material::RawSocketCloudProvider::kWireProtocolMagic;
  header.payload_size = 100000;  // exceeds kMaxPayloadSize

  bad_header.clear();
  header_ptr = (uint8_t*)&header;
  bad_header.insert(bad_header.end(), header_ptr,
                    header_ptr + sizeof(header));

  parsed = xovm::material::RawSocketCloudProvider::parseHeader(bad_header);
  assert(!parsed.has_value() && "Should reject oversized payload");

  return true;
}

}  // namespace xovm::material::test

extern "C" int runRawSocketCloudProviderTests() {
  using namespace xovm::material::test;

  int tests_passed = 0;
  int tests_failed = 0;

  if (testConnectionConfigValidation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }

  if (testMessageHeaderConstruction()) {
    tests_passed++;
  } else {
    tests_failed++;
  }

  if (testChecksumComputation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }

  if (testChecksumValidation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }

  if (testHeaderParsing()) {
    tests_passed++;
  } else {
    tests_failed++;
  }

  if (testHeaderParsingInvalid()) {
    tests_passed++;
  } else {
    tests_failed++;
  }

  return tests_failed == 0 ? 0 : 1;
}
