#include "jit_handler_buffer.h"

#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>

namespace xovm::material {

std::unique_ptr<JitHandlerBuffer> JitHandlerBuffer::allocate(size_t size) {
    if (!size) return nullptr;
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return nullptr;
    const size_t rounded = (size + static_cast<size_t>(page) - 1) /
                           static_cast<size_t>(page) * static_cast<size_t>(page);
    void *address = mmap(nullptr, rounded, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) return nullptr;
    return std::unique_ptr<JitHandlerBuffer>(new JitHandlerBuffer(address, rounded));
}

JitHandlerBuffer::~JitHandlerBuffer() {
    if (address_) {
        mprotect(address_, size_, PROT_READ | PROT_WRITE);
        std::memset(address_, 0, size_);
        munmap(address_, size_);
    }
}

bool JitHandlerBuffer::write(std::span<const uint8_t> bytes) {
    if (!writable_ || bytes.size() > size_) return false;
    std::memcpy(address_, bytes.data(), bytes.size());
    return true;
}

bool JitHandlerBuffer::loadAndSeal(std::span<const uint8_t> code,
                                   std::span<const uint8_t> relocation_descriptors) {
    if (!writable_ || code.empty() || code.size() > size_ ||
        relocation_descriptors.size() % 8 != 0 || !relocation_descriptors.empty())
        return false;
    for (size_t offset = 0; offset < relocation_descriptors.size(); offset += 8) {
        const uint32_t code_offset =
            (static_cast<uint32_t>(relocation_descriptors[offset]) << 24) |
            (static_cast<uint32_t>(relocation_descriptors[offset + 1]) << 16) |
            (static_cast<uint32_t>(relocation_descriptors[offset + 2]) << 8) |
            relocation_descriptors[offset + 3];
        const uint16_t kind = static_cast<uint16_t>(
            (static_cast<uint16_t>(relocation_descriptors[offset + 4]) << 8) |
            relocation_descriptors[offset + 5]);
        const uint16_t width = static_cast<uint16_t>(
            (static_cast<uint16_t>(relocation_descriptors[offset + 6]) << 8) |
            relocation_descriptors[offset + 7]);
        if (kind != 1 || width != 4 || code_offset % 4 != 0 || code_offset > code.size() ||
            width > code.size() - code_offset)
            return false;
    }
    if (!write(code)) return false;
    return sealExecutable();
}

bool JitHandlerBuffer::sealExecutable() {
    if (!writable_ || mprotect(address_, size_, PROT_READ | PROT_EXEC) != 0) return false;
    __builtin___clear_cache(static_cast<char *>(address_),
                            static_cast<char *>(address_) + size_);
    writable_ = false;
    executable_ = true;
    return true;
}

bool JitHandlerBuffer::makeWritable() {
    if (writable_ || mprotect(address_, size_, PROT_READ | PROT_WRITE) != 0) return false;
    writable_ = true;
    executable_ = false;
    return true;
}

bool JitHandlerBuffer::scrub() {
    if (!writable_) return false;
    std::memset(address_, 0, size_);
    return true;
}

} // namespace xovm::material
