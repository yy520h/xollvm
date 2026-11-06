#include "jit_handler_buffer.h"
#include "aarch64_relocation.h"

#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <limits>

namespace xovm::material {

std::unique_ptr<JitHandlerBuffer> JitHandlerBuffer::allocate(size_t size) {
    if (!size) return nullptr;
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return nullptr;
    const size_t pageSize = static_cast<size_t>(page);
    if (size > std::numeric_limits<size_t>::max() - (pageSize - 1)) return nullptr;
    const size_t rounded = (size + pageSize - 1) / pageSize * pageSize;
    void *address = mmap(nullptr, rounded, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) return nullptr;
    return std::unique_ptr<JitHandlerBuffer>(new JitHandlerBuffer(address, rounded));
}

JitHandlerBuffer::~JitHandlerBuffer() {
    if (!address_) return;
    if (!close()) {
        // Never unmap an executable mapping that was not first made writable and
        // scrubbed. A failed transition intentionally leaves the mapping owned by
        // the process rather than releasing plaintext executable pages unsanitized.
        return;
    }
}

bool JitHandlerBuffer::write(std::span<const uint8_t> bytes) {
    if (!address_ || !writable_ || bytes.size() > size_) return false;
    std::memcpy(address_, bytes.data(), bytes.size());
    return true;
}

bool JitHandlerBuffer::loadAndSeal(std::span<const uint8_t> code,
                                   std::span<const uint8_t> relocation_descriptors) {
    if (!address_ || !writable_ || code.empty() || code.size() > size_)
        return false;
    if (!write(code)) return false;
    // Apply any explicit relocations before sealing RX.
    if (!relocation_descriptors.empty()) {
        auto relocs = deserializeAarch64Relocations(relocation_descriptors);
        if (!relocs) return false;
        std::span<uint8_t> rw{static_cast<uint8_t *>(address_), code.size()};
        if (!applyAarch64Relocations(rw, *relocs)) return false;
    }
    return sealExecutable();
}

bool JitHandlerBuffer::sealExecutable() {
    if (!address_ || !writable_ || mprotect(address_, size_, PROT_READ | PROT_EXEC) != 0)
        return false;
    __builtin___clear_cache(static_cast<char *>(address_),
                            static_cast<char *>(address_) + size_);
    writable_ = false;
    executable_ = true;
    return true;
}

bool JitHandlerBuffer::makeWritable() {
    if (!address_ || writable_ ||
        mprotect(address_, size_, PROT_READ | PROT_WRITE) != 0)
        return false;
    writable_ = true;
    executable_ = false;
    return true;
}

bool JitHandlerBuffer::scrub() {
    if (!address_ || !writable_) return false;
    volatile uint8_t *bytes = static_cast<volatile uint8_t *>(address_);
    for (size_t offset = 0; offset < size_; ++offset) bytes[offset] = 0;
    return true;
}

bool JitHandlerBuffer::close() {
    if (!address_) return true;
    if (!writable_ && !makeWritable()) return false;
    if (!scrub()) return false;
    if (munmap(address_, size_) != 0) return false;
    address_ = nullptr;
    size_ = 0;
    writable_ = false;
    executable_ = false;
    return true;
}

} // namespace xovm::material
