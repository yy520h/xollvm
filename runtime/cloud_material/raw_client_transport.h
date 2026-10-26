#ifndef XOVM_RAW_CLIENT_TRANSPORT_H
#define XOVM_RAW_CLIENT_TRANSPORT_H

#include "raw_client_session.h"
#include "raw_socket_transport.h"

#include <cstdint>
#include <span>
#include <string>
#include <variant>

namespace xovm::cloud_material {

struct RawClientTransportError {
    std::string code;
};

class RawClientTransport {
public:
    static std::variant<RawClientTransport, RawClientTransportError> connectAndHandshake(
        uint32_t address_be, uint16_t port_be,
        const RawClientSessionConfig &session_config,
        const xovm::material::RawSyscallTable &syscalls = xovm::material::productionRawSyscalls());

    std::variant<std::vector<uint8_t>, RawClientTransportError> request(
        xovm::material::RawFrameHeader header, std::span<const uint8_t> plaintext);

    bool established() const { return session_.established(); }
    const xovm::material::RawHello &hello() const { return session_.hello(); }
    const std::array<uint8_t, 16> &sessionId() const { return session_.sessionId(); }
    uint32_t keyVersion() const { return session_.keyVersion(); }
    const std::array<uint8_t, 32> &initialStateCommitment() const {
        return session_.initialStateCommitment();
    }
    std::variant<std::array<uint8_t, 32>, RawClientSessionError> deriveGrantKey(
        std::span<const uint8_t, 32> request_commitment) const {
        return session_.deriveGrantKey(request_commitment);
    }
    xovm::material::RawFrameType lastResponseType() const { return last_response_type_; }
    void close() { transport_.close(); }

private:
    RawClientTransport(xovm::material::RawFrameTransport transport,
                       RawClientSession session)
        : transport_(std::move(transport)), session_(std::move(session)) {}

    xovm::material::RawFrameTransport transport_;
    RawClientSession session_;
    xovm::material::RawFrameType last_response_type_ = xovm::material::RawFrameType::Error;
};

} // namespace xovm::cloud_material

#endif
