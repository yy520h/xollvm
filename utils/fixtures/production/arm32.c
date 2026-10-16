#include <stdint.h>
#include <stdio.h>

#ifdef VM_SPEC
#define PROTECTED __attribute__((annotate("obf: " VM_SPEC), noinline))
#else
#define PROTECTED __attribute__((noinline))
#endif

PROTECTED uint32_t protected32(uint32_t a, uint32_t b, const uint32_t* values) {
	uint32_t r = a ^ b;
	for (unsigned i = 0; i < 5; ++i) {
		r += values[i] * (i + 1);
		r = (r << 3) | (r >> 29);
	}
	return r + a * 17 + b;
}

PROTECTED uint64_t protected64(uint64_t a, uint64_t b) {
	return ((a << 17) | (a >> 47)) ^ (b * UINT64_C(0x1234567)) ^ (a + b);
}

PROTECTED double protected_fp(double a, double b) {
	return a > b ? a * 1.25 + b : b * 2.5 - a;
}

static uint32_t reference32(uint32_t a, uint32_t b, const uint32_t* values) {
	uint32_t r = a ^ b;
	for (unsigned i = 0; i < 5; ++i) {
		r += values[i] * (i + 1);
		r = (r << 3) | (r >> 29);
	}
	return r + a * 17 + b;
}

int main(void) {
	const uint32_t values[] = {13, 7, 0, 0xffffffffu, 41};
	for (unsigned i = 0; i < 24; ++i) {
		uint32_t a = i * 1234567u, b = 0xfedcba98u ^ i;
		uint64_t x = ((uint64_t)a << 32) | b;
		uint64_t y = UINT64_C(0x87654321abcdef01) + i;
		if (protected32(a, b, values) != reference32(a, b, values)) return 1;
		if (protected64(x, y) != (((x << 17) | (x >> 47)) ^ (y * UINT64_C(0x1234567)) ^ (x + y))) return 2;
		double da = (double)i - 3.5, db = 8.25;
		double expected = da > db ? da * 1.25 + db : db * 2.5 - da;
		if (protected_fp(da, db) != expected) return 3;
	}
	puts("24 input pairs: i32/i64/ptr/fp equal");
	return 0;
}
