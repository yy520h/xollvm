#ifndef XOVM_MATERIAL_RAW_SOCKET_CLOUD_PROVIDER_H_
#define XOVM_MATERIAL_RAW_SOCKET_CLOUD_PROVIDER_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace xovm::material {

// Raw socket based cloud provider for direct VM communication
// Implements fail-closed security principle with mandatory verification
class RawSocketCloudProvider {
 public:
  // Connection configuration
  struct ConnectionConfig {
    uint32_t remote_ip;           // IPv4 address (network byte order)
    uint16_t remote_port;         // TCP port
    uint32_t connection_timeout;  // milliseconds
    uint32_t max_retries;         // connection retry count
    uint32_t buffer_size;         // send/receive buffer size
  };

  // Message header for wire protocol
  struct MessageHeader {
    uint32_t magic;      // 0xDEADBEEF for validation
    uint16_t message_id; // unique identifier
    uint16_t payload_size;
    uint32_t checksum;   // CRC32 of payload
  };

  static constexpr uint32_t kWireProtocolMagic = 0xDEADBEEF;
  static constexpr size_t kHeaderSize = sizeof(MessageHeader);
  static constexpr size_t kMaxPayloadSize = 65536;

  // Create and establish connection
  static std::optional<RawSocketCloudProvider> create(
      const ConnectionConfig& config);

  // Send message with verification
  bool sendMessage(const std::vector<uint8_t>& payload);

  // Receive message with validation
  std::optional<std::vector<uint8_t>> receiveMessage();

  // Get connection state
  bool isConnected() const { return connected_; }

  // Close connection
  void close();

  // Destructor
  ~RawSocketCloudProvider();

 private:
  RawSocketCloudProvider(const ConnectionConfig& config, int socket_fd)
      : config_(config), socket_fd_(socket_fd), connected_(true),
        message_counter_(0) {}

  ConnectionConfig config_;
  int socket_fd_;
  bool connected_;
  uint16_t message_counter_;

  // Helper: validate connection config
  static bool validateConfig(const ConnectionConfig& config);

  // Helper: compute CRC32 checksum
  static uint32_t computeChecksum(const std::vector<uint8_t>& data);

  // Helper: validate checksum
  static bool validateChecksum(const std::vector<uint8_t>& data,
                               uint32_t expected_checksum);

  // Helper: construct message header
  static MessageHeader constructHeader(uint16_t message_id,
                                       const std::vector<uint8_t>& payload);

  // Helper: parse message header
  static std::optional<MessageHeader> parseHeader(
      const std::vector<uint8_t>& buffer);

  // No copy
  RawSocketCloudProvider(const RawSocketCloudProvider&) = delete;
  RawSocketCloudProvider& operator=(const RawSocketCloudProvider&) = delete;
};

}  // namespace xovm::material

#endif  // XOVM_MATERIAL_RAW_SOCKET_CLOUD_PROVIDER_H_
