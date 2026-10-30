#include "raw_client_transport.h"
#include "dynamic_vm_schema.h"
#include "dynamic_vm_window_provider.h"

#include <arpa/inet.h>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace {

long hostSocket(int domain, int type, int protocol) {
    return ::socket(domain, type, protocol);
}

long hostConnect(int fd, const void *address, unsigned length) {
    return ::connect(fd, static_cast<const sockaddr *>(address), length);
}

long hostSend(int fd, const void *data, size_t length, int flags) {
    return ::send(fd, data, length, flags);
}

long hostRecv(int fd, void *data, size_t length, int flags) {
    return ::recv(fd, data, length, flags);
}

long hostClose(int fd) {
    return ::close(fd);
}

[[noreturn]] void fail(const char *message) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
}

void require(bool condition, const char *message) {
    if (!condition) fail(message);
}

std::array<uint8_t, 32> decodeHash(const std::string &hex) {
    require(hex.size() == 64, "invalid hash length");
    auto nibble = [](char value) -> uint8_t {
        if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<uint8_t>(value - 'a' + 10);
        fail("invalid lowercase hash");
    };
    std::array<uint8_t, 32> result{};
    for (size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<uint8_t>(
            nibble(hex[index * 2]) << 4 | nibble(hex[index * 2 + 1]));
    return result;
}

std::array<uint8_t, 32> requestDigest(std::span<const uint8_t> canonical) {
    constexpr std::string_view domain =
        "xovm/raw-window-acquire/request/v3";
    std::vector<uint8_t> framed;
    framed.reserve(domain.size() + 4 + canonical.size());
    framed.insert(framed.end(), domain.begin(), domain.end());
    const auto size = static_cast<uint32_t>(canonical.size());
    framed.push_back(static_cast<uint8_t>(size >> 24));
    framed.push_back(static_cast<uint8_t>(size >> 16));
    framed.push_back(static_cast<uint8_t>(size >> 8));
    framed.push_back(static_cast<uint8_t>(size));
    framed.insert(framed.end(), canonical.begin(), canonical.end());
    std::array<uint8_t, 32> result{};
    require(SHA256(framed.data(), framed.size(), result.data()) != nullptr,
            "failed to hash window request");
    OPENSSL_cleanse(framed.data(), framed.size());
    return result;
}

std::array<uint8_t, 32> signingPublicKey() {
    std::array<uint8_t, 32> seed{};
    for (size_t index = 0; index < seed.size(); ++index)
        seed[index] = static_cast<uint8_t>(index);
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr,
                                                     seed.data(), seed.size());
    std::array<uint8_t, 32> result{};
    size_t size = result.size();
    const bool ok = key && EVP_PKEY_get_raw_public_key(key, result.data(), &size) == 1 &&
                    size == result.size();
    EVP_PKEY_free(key);
    require(ok, "failed to derive signing public key");
    return result;
}

} // namespace

int main(int argc, char **argv) {
    require(argc == 2 || argc == 4,
            "usage: raw-client PORT [BUILD_ID REGION_ID]");
    const auto port = static_cast<uint16_t>(std::stoul(argv[1]));
    const bool exercise_window_acquire = argc == 4;
    const xovm::material::RawSyscallTable host_syscalls{
        hostSocket, hostConnect, hostSend, hostRecv, hostClose};

    xovm::cloud_material::RawClientSessionConfig config;
    config.hello.software_id = "fixture.software";
    config.hello.build_id = exercise_window_acquire ? argv[2] : "22";
    config.hello.request_id.fill(0x44);
    config.server_signing_public_key = signingPublicKey();
    config.random_bytes = [](size_t size) {
        return std::variant<std::vector<uint8_t>, xovm::cloud_material::RawClientSessionError>(
            std::vector<uint8_t>(size, 0x33));
    };

    auto connected = xovm::cloud_material::RawClientTransport::connectAndHandshake(
        htonl(INADDR_LOOPBACK), htons(port), config, host_syscalls);
    require(std::holds_alternative<xovm::cloud_material::RawClientTransport>(connected),
            "raw handshake failed");
    auto client = std::get<xovm::cloud_material::RawClientTransport>(std::move(connected));

    xovm::material::RawFrameHeader announcement{};
    announcement.type = xovm::material::RawFrameType::Announcement;
    announcement.session_id = client.sessionId();
    announcement.flags = client.keyVersion();
    auto response = client.request(announcement, {});
    require(std::holds_alternative<std::vector<uint8_t>>(response),
            "announcement request failed");
    const auto &announcement_bytes = std::get<std::vector<uint8_t>>(response);
    require(client.lastResponseType() == xovm::material::RawFrameType::Announcement,
            "unexpected announcement response type");
    require(announcement_bytes.size() > 2 && announcement_bytes[0] == 0 &&
                announcement_bytes[1] == 1,
            "invalid announcement response");

    uint64_t next_sequence = 1;
    if (exercise_window_acquire) {
        xovm::material::WindowAcquireRequest request{};
        request.request_id.fill(0x66);
        request.build_id = decodeHash(argv[2]);
        request.region_id = decodeHash(argv[3]);
        request.artifact_hash.fill(0x22);
        request.selector.abi_id = 7;
        request.selector.abi_hash.fill(0xa1);
        request.selector.graph_commitment.fill(0xa2);
        request.selector.node_id = 1;
        request.selector.shard_id = 1;
        request.selector.variant_id = 1;
        request.selector.semantic =
            xovm::material::ContinuationNodeSemanticV2::LoadI32;
        request.selector.status =
            xovm::material::ContinuationNodeStatusV2::Continue;
        request.selector.bytecode_size = 6;
        request.selector.bytecode_block_commitment.fill(0xb1);
        request.selector.shard_size = 16;
        request.selector.handler_shard_commitment.fill(0xc1);
        request.selector.next_node_id = 2;
        request.selector.transition_tail_commitment.fill(0xd1);
        request.generation = 1;
        request.window_id = 1;
        request.previous_state_hash = client.initialStateCommitment();
        const auto encoded = xovm::material::encodeWindowAcquireRequest(request);
        require(!encoded.empty(), "failed to encode window request");
        xovm::material::RawFrameHeader algorithm{};
        algorithm.type = xovm::material::RawFrameType::AlgorithmAcquire;
        algorithm.session_id = client.sessionId();
        algorithm.flags = client.keyVersion();
        algorithm.sequence = next_sequence++;
        auto acquired = client.request(algorithm, encoded);
        require(std::holds_alternative<std::vector<uint8_t>>(acquired),
                "algorithm request failed");
        require(client.lastResponseType() ==
                    xovm::material::RawFrameType::AlgorithmAcquire,
                "algorithm request returned an error");
        const auto &grant_bytes = std::get<std::vector<uint8_t>>(acquired);
        const auto grant = xovm::material::decodeWindowGrant(grant_bytes);
        require(grant.has_value(), "algorithm response was not a canonical grant");
        require(grant->build_id == request.build_id &&
                    grant->region_id == request.region_id &&
                    grant->artifact_hash == request.artifact_hash &&
                    grant->selector == request.selector &&
                    grant->session_id == client.sessionId() &&
                    grant->generation == request.generation &&
                    grant->window_id == request.window_id &&
                    grant->previous_state_hash == request.previous_state_hash &&
                    grant->key_version == client.keyVersion(),
                "window grant binding mismatch");
        const auto digest = requestDigest(encoded);
        auto grant_key = client.deriveGrantKey(digest);
        require(std::holds_alternative<std::array<uint8_t, 32>>(grant_key),
                "failed to derive grant key");
        auto &key = std::get<std::array<uint8_t, 32>>(grant_key);
        auto material = xovm::material::decryptWindowMaterial(*grant, key);
        OPENSSL_cleanse(key.data(), key.size());
        require(material.has_value(), "window material authentication failed");
        xovm::material::secureClear(*material);

        algorithm.sequence = next_sequence++;
        auto retry = client.request(algorithm, encoded);
        require(std::holds_alternative<std::vector<uint8_t>>(retry) &&
                    client.lastResponseType() ==
                        xovm::material::RawFrameType::AlgorithmAcquire &&
                    std::get<std::vector<uint8_t>>(retry) == grant_bytes,
                "exact window retry did not return committed bytes");

        auto conflict_request = request;
        conflict_request.window_id = 2;
        conflict_request.previous_state_hash = grant->next_state_hash;
        const auto conflict_bytes =
            xovm::material::encodeWindowAcquireRequest(conflict_request);
        require(!conflict_bytes.empty(), "failed to encode conflicting request");
        algorithm.sequence = next_sequence++;
        auto conflict = client.request(algorithm, conflict_bytes);
        require(std::holds_alternative<std::vector<uint8_t>>(conflict) &&
                    client.lastResponseType() == xovm::material::RawFrameType::Error,
                "same-ID mutation did not fail closed");
        const std::vector<uint8_t> expected_conflict{
            0xff, 0xff, 0x00, 0x10, 'r', 'e', 'q', 'u', 'e', 's', 't', '_',
            'c', 'o', 'n', 'f', 'l', 'i', 'c', 't'};
        require(std::get<std::vector<uint8_t>>(conflict) == expected_conflict,
                "same-ID mutation did not report request_conflict");

        auto replayed_hello =
            xovm::cloud_material::RawClientTransport::connectAndHandshake(
                htonl(INADDR_LOOPBACK), htons(port), config, host_syscalls);
        require(std::holds_alternative<
                    xovm::cloud_material::RawClientTransportError>(replayed_hello),
                "identical raw hello was replayed");
    }

    const uint8_t malformed[] = {1};
    announcement.sequence = next_sequence;
    auto error = client.request(announcement, malformed);
    require(std::holds_alternative<std::vector<uint8_t>>(error),
            "malformed request failed at transport layer");
    const auto &error_bytes = std::get<std::vector<uint8_t>>(error);
    require(client.lastResponseType() == xovm::material::RawFrameType::Error,
            "malformed request did not produce error frame");
    require(error_bytes.size() >= 4 && error_bytes[0] == 0xff &&
                error_bytes[1] == 0xff,
            "malformed request returned invalid error payload");
    client.close();
    return 0;
}
