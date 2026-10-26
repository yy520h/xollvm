#include "raw_socket_transport.h"

#include <algorithm>
#include <cerrno>

namespace xovm::material {
namespace {

struct Ipv4SocketAddress {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t padding[8]{};
};

constexpr int kAfInet = 2;
constexpr int kSockStream = 1;
constexpr int kEintr = 4;
constexpr int kEagain = 11;

} // namespace

RawSocketFd::RawSocketFd(RawSocketFd &&other) noexcept
    : fd_(other.fd_), syscalls_(other.syscalls_) {
    other.fd_ = -1;
    other.syscalls_ = nullptr;
}

RawSocketFd &RawSocketFd::operator=(RawSocketFd &&other) noexcept {
    if (this == &other) return *this;
    close();
    fd_ = other.fd_;
    syscalls_ = other.syscalls_;
    other.fd_ = -1;
    other.syscalls_ = nullptr;
    return *this;
}

RawSocketFd::~RawSocketFd() { close(); }

RawSocketFd RawSocketFd::connectIpv4(uint32_t address_be, uint16_t port_be,
                                     const RawSyscallTable &syscalls,
                                     RawSocketResult *result) {
    RawSocketResult local;
    const long fd = syscalls.socket(kAfInet, kSockStream, 0);
    if (fd < 0) {
        local.error = RawSocketError::System;
        local.system_error = -fd;
        if (result) *result = local;
        return {};
    }
    Ipv4SocketAddress address{static_cast<uint16_t>(kAfInet), port_be, address_be, {}};
    const long connected = syscalls.connect(static_cast<int>(fd), &address, sizeof(address));
    if (connected < 0) {
        local.error = RawSocketError::System;
        local.system_error = -connected;
        syscalls.close(static_cast<int>(fd));
        if (result) *result = local;
        return {};
    }
    local.transferred = 0;
    if (result) *result = local;
    return RawSocketFd(static_cast<int>(fd), syscalls);
}

RawSocketResult RawSocketFd::sendAll(std::span<const uint8_t> bytes) {
    if (fd_ < 0 || !syscalls_) return {RawSocketError::InvalidArgument, 0, 0};
    size_t offset = 0;
    while (offset < bytes.size()) {
        const long sent = syscalls_->send(fd_, bytes.data() + offset, bytes.size() - offset, 0);
        if (sent > 0) {
            offset += static_cast<size_t>(sent);
            continue;
        }
        if (sent == -kEintr) continue;
        if (sent == -kEagain) return {RawSocketError::Interrupted, kEagain, offset};
        if (sent == 0) return {RawSocketError::PeerClosed, 0, offset};
        return {RawSocketError::System, -sent, offset};
    }
    return {RawSocketError::None, 0, offset};
}

RawSocketResult RawSocketFd::recvExact(std::span<uint8_t> bytes) {
    if (fd_ < 0 || !syscalls_) return {RawSocketError::InvalidArgument, 0, 0};
    size_t offset = 0;
    while (offset < bytes.size()) {
        const long received = syscalls_->recv(fd_, bytes.data() + offset, bytes.size() - offset, 0);
        if (received > 0) {
            offset += static_cast<size_t>(received);
            continue;
        }
        if (received == -kEintr) continue;
        if (received == -kEagain) return {RawSocketError::Interrupted, kEagain, offset};
        if (received == 0) return {RawSocketError::PeerClosed, 0, offset};
        return {RawSocketError::System, -received, offset};
    }
    return {RawSocketError::None, 0, offset};
}

void RawSocketFd::close() {
    if (fd_ >= 0 && syscalls_) syscalls_->close(fd_);
    fd_ = -1;
    syscalls_ = nullptr;
}

RawSocketResult RawFrameTransport::sendFrame(const RawFrameHeader &header,
                                             std::span<const uint8_t> payload) {
    const auto frame = encodeRawFrame(header, payload);
    if (frame.empty()) return {RawSocketError::FrameTooLarge, 0, 0};
    return socket_.sendAll(frame);
}

std::variant<std::vector<uint8_t>, RawSocketError>
RawFrameTransport::receiveFrame(RawFrameHeader &header) {
    std::array<uint8_t, kRawFrameHeaderSize> encoded{};
    const auto headerResult = socket_.recvExact(encoded);
    if (!headerResult) return headerResult.error;
    auto decoded = decodeRawFrameHeader(encoded);
    if (auto *error = std::get_if<RawProtocolError>(&decoded)) {
        (void)error;
        return RawSocketError::Protocol;
    }
    header = std::get<RawFrameHeader>(decoded);
    std::vector<uint8_t> payload(header.payload_length);
    const auto payloadResult = socket_.recvExact(payload);
    if (!payloadResult) return payloadResult.error;
    return payload;
}

} // namespace xovm::material
