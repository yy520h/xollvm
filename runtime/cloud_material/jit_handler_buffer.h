#ifndef XOVM_JIT_HANDLER_BUFFER_H
#define XOVM_JIT_HANDLER_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace xovm::material {

class JitHandlerBuffer {
public:
    static std::unique_ptr<JitHandlerBuffer> allocate(size_t size);
    ~JitHandlerBuffer();
    JitHandlerBuffer(const JitHandlerBuffer &) = delete;
    JitHandlerBuffer &operator=(const JitHandlerBuffer &) = delete;

    bool write(std::span<const uint8_t> bytes);
    bool loadAndSeal(std::span<const uint8_t> code,
                     std::span<const uint8_t> relocation_descriptors);
    bool sealExecutable();
    bool makeWritable();
    bool scrub();
    // Returns the mapping to RW, scrubs it, and only then releases ownership.
    // On a protection or unmap failure the mapping remains owned for retry.
    bool close();
    bool isWritable() const { return writable_; }
    bool isExecutable() const { return executable_; }
    bool isClosed() const { return address_ == nullptr; }
    void *address() const { return address_; }

private:
    JitHandlerBuffer(void *address, size_t size) : address_(address), size_(size) {}
    void *address_ = nullptr;
    size_t size_ = 0;
    bool writable_ = true;
    bool executable_ = false;
};

} // namespace xovm::material

#endif
