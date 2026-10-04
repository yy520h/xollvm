/*
 * integrity_sha256.c — freestanding SHA-256 for the XOLLVM ELF integrity
 * manifest runtime checker.
 *
 * No libc, no OpenSSL: the runtime constructor hashes the loaded executable
 * ranges and compares against the compiler-sealed digest. Compiled to LLVM
 * bitcode and linked only into modules with a strict sensitive region.
 *
 * Internal entry point (bitcode linked, then called by emitted IR):
 *   void __xollvm_integrity_sha256(const uint8_t *data, size_t len,
 *                                  uint8_t out[32]);
 */

#include <stddef.h>
#include <stdint.h>

#define XOL_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t kK[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void xol_transform(uint32_t st[8], const uint8_t blk[64]) {
	uint32_t w[64];
	for (int i = 0; i < 16; ++i)
		w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
		       ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
	for (int i = 16; i < 64; ++i) {
		uint32_t s0 = XOL_ROTR(w[i - 15], 7) ^ XOL_ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = XOL_ROTR(w[i - 2], 17) ^ XOL_ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
	uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
	for (int i = 0; i < 64; ++i) {
		uint32_t S1 = XOL_ROTR(e, 6) ^ XOL_ROTR(e, 11) ^ XOL_ROTR(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t t1 = h + S1 + ch + kK[i] + w[i];
		uint32_t S0 = XOL_ROTR(a, 2) ^ XOL_ROTR(a, 13) ^ XOL_ROTR(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	st[0] += a; st[1] += b; st[2] += c; st[3] += d;
	st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

// Streaming context so the runtime can hash a mapped range while treating an
// interior window (the manifest) as zero without copying the whole segment.
typedef struct {
	uint32_t st[8];
	uint8_t buf[64];
	size_t buflen;
	uint64_t total;
} xol_sha256_ctx;

void __xollvm_integrity_sha256_init(xol_sha256_ctx *c) {
	static const uint32_t iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	for (int j = 0; j < 8; ++j) c->st[j] = iv[j];
	c->buflen = 0;
	c->total = 0;
}

void __xollvm_integrity_sha256_update(xol_sha256_ctx *c, const uint8_t *data, size_t len) {
	c->total += len;
	if (c->buflen) {
		while (len && c->buflen < 64) { c->buf[c->buflen++] = *data++; --len; }
		if (c->buflen == 64) { xol_transform(c->st, c->buf); c->buflen = 0; }
	}
	while (len >= 64) { xol_transform(c->st, data); data += 64; len -= 64; }
	while (len) { c->buf[c->buflen++] = *data++; --len; }
}

void __xollvm_integrity_sha256_update_zeros(xol_sha256_ctx *c, size_t count) {
	static const uint8_t Z[64] = {0};
	while (count >= 64) { __xollvm_integrity_sha256_update(c, Z, 64); count -= 64; }
	if (count) __xollvm_integrity_sha256_update(c, Z, count);
}

void __xollvm_integrity_sha256_final(xol_sha256_ctx *c, uint8_t out[32]) {
	uint64_t bits = c->total * 8;
	// Append the 0x80 terminator directly into the block buffer.
	c->buf[c->buflen++] = 0x80;
	if (c->buflen > 56) {
		while (c->buflen < 64) c->buf[c->buflen++] = 0;
		xol_transform(c->st, c->buf);
		c->buflen = 0;
	}
	while (c->buflen < 56) c->buf[c->buflen++] = 0;
	// Message length is appended big-endian.
	for (int j = 7; j >= 0; --j) c->buf[c->buflen++] = (uint8_t)(bits >> (j * 8));
	xol_transform(c->st, c->buf);
	c->buflen = 0;
	for (int j = 0; j < 8; ++j) {
		out[j * 4] = (uint8_t)(c->st[j] >> 24);
		out[j * 4 + 1] = (uint8_t)(c->st[j] >> 16);
		out[j * 4 + 2] = (uint8_t)(c->st[j] >> 8);
		out[j * 4 + 3] = (uint8_t)(c->st[j]);
	}
}

void __xollvm_integrity_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
	xol_sha256_ctx c;
	__xollvm_integrity_sha256_init(&c);
	__xollvm_integrity_sha256_update(&c, data, len);
	__xollvm_integrity_sha256_final(&c, out);
}
