#ifndef XOVM_RAW_PROTOCOL_H
#define XOVM_RAW_PROTOCOL_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace xovm::material {

inline constexpr uint16_t kRawProtocolVersion = 1;
inline constexpr uint32_t kRawFrameMagic = 0x4d564f58; // XOVM
inline constexpr size_t kRawFrameHeaderSize = 44;
inline constexpr size_t kRawMaxFramePayload = 1024 * 1024;

enum class RawFrameType : uint16_t {
    Announcement = 1,
    Update = 2,
    AlgorithmAcquire = 3,
    RemoteVariables = 4,
    LoginAccount = 5,
    LoginCard = 6,
    Error = 255,
};

struct RawFrameHeader {
    uint16_t version = kRawProtocolVersion;
    RawFrameType type = RawFrameType::Error;
    uint32_t flags = 0;
    std::array<uint8_t, 16> session_id{};
    uint64_t sequence = 0;
    uint32_t payload_length = 0;
};

struct RawHello {
    uint16_t version = kRawProtocolVersion;
    std::string software_id;
    std::string build_id;
    std::array<uint8_t, 32> client_nonce{};
    std::array<uint8_t, 32> client_ephemeral_public{};
    std::array<uint8_t, 16> request_id{};
    uint16_t cipher_suite = 1;
};

struct RawServerHello {
    uint16_t version = kRawProtocolVersion;
    std::array<uint8_t, 16> session_id{};
    std::array<uint8_t, 32> server_nonce{};
    std::array<uint8_t, 32> server_ephemeral_public{};
    uint64_t counter = 0;
    uint32_t key_version = 0;
    uint64_t expires_at_ms = 0;
    std::array<uint8_t, 64> signature{};
};

struct RawSessionTranscript {
    RawHello hello;
    RawServerHello server_hello;
};

struct RawSessionKeys {
    std::array<uint8_t, 32> client_to_server{};
    std::array<uint8_t, 32> server_to_client{};
    std::array<uint8_t, 32> material{};
    std::array<uint8_t, 32> control{};
};

enum class RawFrameDirection : uint8_t {
    ClientToServer = 1,
    ServerToClient = 2,
};

struct RawProtocolError {
    std::string code;
};

std::vector<uint8_t> encodeRawFrameHeader(const RawFrameHeader &header);
std::variant<RawFrameHeader, RawProtocolError>
decodeRawFrameHeader(std::span<const uint8_t> bytes);

std::vector<uint8_t> encodeRawHello(const RawHello &hello);
std::variant<RawHello, RawProtocolError> decodeRawHello(std::span<const uint8_t> bytes);
std::vector<uint8_t> encodeRawServerHello(const RawServerHello &hello);
std::variant<RawServerHello, RawProtocolError>
decodeRawServerHello(std::span<const uint8_t> bytes);
std::vector<uint8_t> encodeRawTranscript(const RawSessionTranscript &transcript);
std::array<uint8_t, 32> hashRawTranscript(const RawSessionTranscript &transcript);
std::vector<uint8_t> encodeRawFrameAad(const RawFrameHeader &header,
                                       std::span<const uint8_t, 32> transcript_hash,
                                       RawFrameDirection direction);

std::variant<RawSessionKeys, RawProtocolError>
deriveRawSessionKeys(const RawSessionTranscript &transcript,
                     std::span<const uint8_t, 32> shared_secret);

std::variant<std::array<uint8_t, 32>, RawProtocolError>
deriveRawSharedSecret(std::span<const uint8_t, 32> private_key,
                      std::span<const uint8_t, 32> peer_public_key);

bool verifyRawServerHello(const RawSessionTranscript &transcript,
                          std::span<const uint8_t, 32> server_signing_public_key);

} // namespace xovm::material

#endif
