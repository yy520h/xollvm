#include "raw_client_transport.h"

#include <array>

namespace xovm::cloud_material {
namespace {

std::array<uint8_t, 2> encodeLength(size_t size) {
    return {static_cast<uint8_t>(size >> 8), static_cast<uint8_t>(size)};
}

bool validLength(std::span<const uint8_t> bytes) {
    return bytes.size() <= UINT16_MAX && !bytes.empty();
}

std::variant<RawClientTransport, RawClientTransportError> fail(std::string code) {
    return RawClientTransportError{std::move(code)};
}

} // namespace

std::variant<RawClientTransport, RawClientTransportError>
RawClientTransport::connectAndHandshake(
    uint32_t address_be, uint16_t port_be,
    const RawClientSessionConfig &session_config,
    const xovm::material::RawSyscallTable &syscalls) {
    auto session_result = RawClientSession::create(session_config);
    if (std::holds_alternative<RawClientSessionError>(session_result))
        return fail(std::get<RawClientSessionError>(std::move(session_result)).code);
    auto session = std::get<RawClientSession>(std::move(session_result));

    xovm::material::RawSocketResult socket_result;
    auto socket = xovm::material::RawSocketFd::connectIpv4(address_be, port_be, syscalls,
                                                            &socket_result);
    if (!socket_result || socket.get() < 0) return fail("connect_failed");
    xovm::material::RawFrameTransport transport(std::move(socket));

    const auto hello = xovm::material::encodeRawHello(session.hello());
    if (!validLength(hello)) return fail("invalid_hello");
    const auto hello_length = encodeLength(hello.size());
    // HELLO uses a separate bounded length prefix, unlike encrypted frames.
    if (!transport.sendBytes(hello_length) || !transport.sendBytes(hello))
        return fail("hello_send_failed");
    std::array<uint8_t, 2> server_length{};
    if (!transport.recvBytes(server_length)) return fail("server_hello_receive_failed");
    const size_t server_size = (static_cast<size_t>(server_length[0]) << 8) | server_length[1];
    if (server_size == 0 || server_size > 4096) return fail("invalid_server_hello");
    std::vector<uint8_t> encoded_server_hello(server_size);
    if (!transport.recvBytes(encoded_server_hello)) return fail("server_hello_receive_failed");
    auto decoded = xovm::material::decodeRawServerHello(encoded_server_hello);
    if (std::holds_alternative<xovm::material::RawProtocolError>(decoded))
        return fail(std::get<xovm::material::RawProtocolError>(std::move(decoded)).code);
    if (!session.acceptServerHello(std::get<xovm::material::RawServerHello>(std::move(decoded))))
        return fail("server_hello_rejected");
    return RawClientTransport(std::move(transport), std::move(session));
}

std::variant<std::vector<uint8_t>, RawClientTransportError> RawClientTransport::request(
    xovm::material::RawFrameHeader header, std::span<const uint8_t> plaintext) {
    if (!session_.established()) return RawClientTransportError{"session_not_established"};
    header.payload_length = static_cast<uint32_t>(plaintext.size() + 16);
    auto encrypted = session_.encrypt(header, plaintext);
    if (std::holds_alternative<RawClientSessionError>(encrypted))
        return RawClientTransportError{std::get<RawClientSessionError>(std::move(encrypted)).code};
    const auto payload = std::get<std::vector<uint8_t>>(std::move(encrypted));
    auto sent = transport_.sendFrame(header, payload);
    if (!sent) return RawClientTransportError{"send_failed"};
    xovm::material::RawFrameHeader response_header;
    auto response = transport_.receiveFrame(response_header);
    if (std::holds_alternative<xovm::material::RawSocketError>(response))
        return RawClientTransportError{"receive_failed"};
    const auto &wire = std::get<std::vector<uint8_t>>(response);
    if (wire.size() < 16) return RawClientTransportError{"invalid_response"};
    last_response_type_ = response_header.type;
    auto opened = session_.decrypt(
        response_header,
        std::span<const uint8_t>(wire.data(), wire.size() - 16),
        std::span<const uint8_t, 16>(wire.data() + wire.size() - 16, 16));
    if (std::holds_alternative<RawClientSessionError>(opened))
        return RawClientTransportError{std::get<RawClientSessionError>(std::move(opened)).code};
    return std::get<std::vector<uint8_t>>(std::move(opened));
}

} // namespace xovm::cloud_material
