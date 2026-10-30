#include "runtime/cloud_material/raw_socket_cloud_provider.h"

#include <arpa/inet.h>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

namespace xovm::material {

bool RawSocketCloudProvider::validateConfig(const ConnectionConfig& config) {
  if (config.remote_port == 0) {
    return false;
  }
  if (config.connection_timeout == 0 || config.connection_timeout > 60000) {
    return false;
  }
  if (config.max_retries == 0 || config.max_retries > 10) {
    return false;
  }
  if (config.buffer_size == 0 || config.buffer_size > 1048576) {
    return false;
  }
  return true;
}

uint32_t RawSocketCloudProvider::computeChecksum(
    const std::vector<uint8_t>& data) {
  // Simple CRC32 computation
  uint32_t crc = 0xFFFFFFFF;
  for (uint8_t byte : data) {
    crc ^= byte;
    for (int i = 0; i < 8; ++i) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xEDB88320;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc ^ 0xFFFFFFFF;
}

bool RawSocketCloudProvider::validateChecksum(const std::vector<uint8_t>& data,
                                              uint32_t expected_checksum) {
  return computeChecksum(data) == expected_checksum;
}

RawSocketCloudProvider::MessageHeader RawSocketCloudProvider::constructHeader(
    uint16_t message_id, const std::vector<uint8_t>& payload) {
  MessageHeader header;
  header.magic = kWireProtocolMagic;
  header.message_id = message_id;
  header.payload_size = static_cast<uint16_t>(payload.size());
  header.checksum = computeChecksum(payload);
  return header;
}

std::optional<RawSocketCloudProvider::MessageHeader>
RawSocketCloudProvider::parseHeader(const std::vector<uint8_t>& buffer) {
  if (buffer.size() < kHeaderSize) {
    return std::nullopt;
  }

  MessageHeader header;
  std::memcpy(&header, buffer.data(), kHeaderSize);

  if (header.magic != kWireProtocolMagic) {
    return std::nullopt;
  }
  if (header.payload_size > kMaxPayloadSize) {
    return std::nullopt;
  }

  return header;
}

std::optional<RawSocketCloudProvider> RawSocketCloudProvider::create(
    const ConnectionConfig& config) {
  if (!validateConfig(config)) {
    return std::nullopt;
  }

  int socket_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_fd < 0) {
    return std::nullopt;
  }

  struct sockaddr_in server_addr;
  std::memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(config.remote_port);
  server_addr.sin_addr.s_addr = config.remote_ip;

  if (::connect(socket_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0) {
    ::close(socket_fd);
    return std::nullopt;
  }

  return RawSocketCloudProvider(config, socket_fd);
}

bool RawSocketCloudProvider::sendMessage(
    const std::vector<uint8_t>& payload) {
  if (!connected_ || payload.empty() || payload.size() > kMaxPayloadSize) {
    return false;
  }

  // Construct header
  MessageHeader header = constructHeader(++message_counter_, payload);

  // Send header
  ssize_t bytes_sent = ::send(socket_fd_, &header, kHeaderSize, 0);
  if (bytes_sent != static_cast<ssize_t>(kHeaderSize)) {
    connected_ = false;
    return false;
  }

  // Send payload
  bytes_sent = ::send(socket_fd_, payload.data(), payload.size(), 0);
  if (bytes_sent != static_cast<ssize_t>(payload.size())) {
    connected_ = false;
    return false;
  }

  return true;
}

std::optional<std::vector<uint8_t>> RawSocketCloudProvider::receiveMessage() {
  if (!connected_) {
    return std::nullopt;
  }

  // Receive header
  std::vector<uint8_t> header_buffer(kHeaderSize);
  ssize_t bytes_recv =
      ::recv(socket_fd_, header_buffer.data(), kHeaderSize, 0);
  if (bytes_recv != static_cast<ssize_t>(kHeaderSize)) {
    connected_ = false;
    return std::nullopt;
  }

  auto header = parseHeader(header_buffer);
  if (!header.has_value()) {
    connected_ = false;
    return std::nullopt;
  }

  // Receive payload
  std::vector<uint8_t> payload(header->payload_size);
  bytes_recv = ::recv(socket_fd_, payload.data(), header->payload_size, 0);
  if (bytes_recv != static_cast<ssize_t>(header->payload_size)) {
    connected_ = false;
    return std::nullopt;
  }

  // Validate checksum
  if (!validateChecksum(payload, header->checksum)) {
    connected_ = false;
    return std::nullopt;
  }

  return payload;
}

void RawSocketCloudProvider::close() {
  if (connected_ && socket_fd_ >= 0) {
    ::close(socket_fd_);
    connected_ = false;
  }
}

RawSocketCloudProvider::~RawSocketCloudProvider() {
  close();
}

}  // namespace xovm::material
