#ifndef XOVM_RAW_SOCKET_TRANSPORT_H
#define XOVM_RAW_SOCKET_TRANSPORT_H

#include "raw_frame.h"
#include "raw_socket_syscall_aarch64.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace xovm::material {

enum class RawSocketError {
    None,
    InvalidArgument,
    System,
    Interrupted,
    PeerClosed,
    FrameTooLarge,
    Partial,
    Protocol,
};

struct RawSocketResult {
    RawSocketError error = RawSocketError::None;
    long system_error = 0;
    size_t transferred = 0;
    explicit operator bool() const { return error == RawSocketError::None; }
};

class RawSocketFd {
public:
    RawSocketFd() = default;
    RawSocketFd(int fd, const RawSyscallTable &syscalls) : fd_(fd), syscalls_(&syscalls) {}
    RawSocketFd(const RawSocketFd &) = delete;
    RawSocketFd &operator=(const RawSocketFd &) = delete;
    RawSocketFd(RawSocketFd &&other) noexcept;
    RawSocketFd &operator=(RawSocketFd &&other) noexcept;
    ~RawSocketFd();

    static RawSocketFd connectIpv4(uint32_t address_be, uint16_t port_be,
                                   const RawSyscallTable &syscalls = productionRawSyscalls(),
                                   RawSocketResult *result = nullptr);
    RawSocketResult sendAll(std::span<const uint8_t> bytes);
    RawSocketResult recvExact(std::span<uint8_t> bytes);
    void close();
    int get() const { return fd_; }

private:
    int fd_ = -1;
    const RawSyscallTable *syscalls_ = nullptr;
};

class RawFrameTransport {
public:
    explicit RawFrameTransport(RawSocketFd socket) : socket_(std::move(socket)) {}
    RawSocketResult sendBytes(std::span<const uint8_t> bytes) { return socket_.sendAll(bytes); }
    RawSocketResult recvBytes(std::span<uint8_t> bytes) { return socket_.recvExact(bytes); }
    RawSocketResult sendFrame(const RawFrameHeader &header,
                              std::span<const uint8_t> payload);
    std::variant<std::vector<uint8_t>, RawSocketError> receiveFrame(RawFrameHeader &header);
    void close() { socket_.close(); }

private:
    RawSocketFd socket_;
};

} // namespace xovm::material

#endif
