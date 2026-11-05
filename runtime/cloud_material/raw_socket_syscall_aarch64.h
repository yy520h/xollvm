#ifndef XOVM_RAW_SOCKET_SYSCALL_AARCH64_H
#define XOVM_RAW_SOCKET_SYSCALL_AARCH64_H

#include <cstddef>
#include <cstdint>

namespace xovm::material {

struct RawSyscallTable {
    long (*socket)(int domain, int type, int protocol);
    long (*connect)(int fd, const void *address, unsigned length);
    long (*send)(int fd, const void *data, size_t length, int flags);
    long (*recv)(int fd, void *data, size_t length, int flags);
    long (*close)(int fd);
};

const RawSyscallTable &productionRawSyscalls();

} // namespace xovm::material

#endif
