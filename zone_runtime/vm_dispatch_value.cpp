#include "vm_dispatch_value.h"

#include <chrono>
#include <cstdio>
#include <openssl/sha.h>

#if defined(__aarch64__)
static inline uint64_t readArchTick() {
	uint64_t value = 0;
	asm volatile("mrs %0, CNTVCT_EL0" : "=r"(value));
	return value;
}
#elif defined(__x86_64__)
static inline uint64_t readArchTick() {
	uint32_t lo = 0;
	uint32_t hi = 0;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return (static_cast<uint64_t>(hi) << 32) | lo;
}
#else
static inline uint64_t readArchTick() {
	return static_cast<uint64_t>(
		std::chrono::steady_clock::now().time_since_epoch().count());
}
#endif

namespace xollvm {

uint64_t readClientTick() { return readArchTick(); }

std::string computeWindowId(uint64_t serverTime, uint64_t windowSeconds) {
	if (windowSeconds == 0)
		windowSeconds = 1;
	char buffer[32];
	std::snprintf(buffer, sizeof(buffer), "%llu",
		static_cast<unsigned long long>(serverTime / windowSeconds));
	return buffer;
}

std::string deriveDispatchKey(const std::string& signedBlob, uint64_t clientTick) {
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX context;
	SHA256_Init(&context);
	SHA256_Update(&context, "dispatch-v1\0", 12);
	SHA256_Update(&context, signedBlob.data(), signedBlob.size());
	SHA256_Update(&context, &clientTick, sizeof(clientTick));
	SHA256_Final(digest, &context);
	static const char hex[] = "0123456789abcdef";
	std::string out;
	out.resize(SHA256_DIGEST_LENGTH * 2);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		out[i * 2] = hex[digest[i] >> 4];
		out[i * 2 + 1] = hex[digest[i] & 0x0f];
	}
	return out;
}

}  // namespace xollvm
