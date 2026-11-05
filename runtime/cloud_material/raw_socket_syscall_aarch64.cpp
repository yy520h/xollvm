#include "raw_socket_syscall_aarch64.h"

#include <cerrno>

namespace xovm::material {
namespace {

#if defined(__aarch64__)
long syscall6(long number, long a0 = 0, long a1 = 0, long a2 = 0,
              long a3 = 0, long a4 = 0, long a5 = 0) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2),
                     "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}
#else
long unsupportedSocket(int, int, int) { return -ENOSYS; }
long unsupportedConnect(int, const void *, unsigned) { return -ENOSYS; }
long unsupportedSend(int, const void *, size_t, int) { return -ENOSYS; }
long unsupportedRecv(int, void *, size_t, int) { return -ENOSYS; }
long unsupportedClose(int) { return -ENOSYS; }
#endif

#if defined(__aarch64__)
long rawSocket(int domain, int type, int protocol) {
    return syscall6(198, domain, type, protocol);
}
long rawConnect(int fd, const void *address, unsigned length) {
    return syscall6(203, fd, reinterpret_cast<long>(address), length);
}
long rawSend(int fd, const void *data, size_t length, int flags) {
    return syscall6(206, fd, reinterpret_cast<long>(data), length, flags, 0, 0);
}
long rawRecv(int fd, void *data, size_t length, int flags) {
    return syscall6(207, fd, reinterpret_cast<long>(data), length, flags, 0, 0);
}
long rawClose(int fd) { return syscall6(57, fd); }
#endif

} // namespace

const RawSyscallTable &productionRawSyscalls() {
#if defined(__aarch64__)
    static const RawSyscallTable table = {rawSocket, rawConnect, rawSend, rawRecv, rawClose};
#else
    static const RawSyscallTable table = {
        unsupportedSocket, unsupportedConnect, unsupportedSend, unsupportedRecv, unsupportedClose};
#endif
    return table;
}

} // namespace xovm::material
