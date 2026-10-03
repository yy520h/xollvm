extern "C" int fixture_verify(const unsigned char *, unsigned long);
extern "C" void fixture_transport(const unsigned char *, unsigned long);

extern "C" __attribute__((noinline)) int
fixture_compare(const char *left, const char *right) {
    while (*left && *left == *right) {
        ++left;
        ++right;
    }
    return static_cast<unsigned char>(*left) -
           static_cast<unsigned char>(*right);
}

extern "C" __attribute__((noinline)) int fixture_success() {
    return 1;
}

extern "C" __attribute__((noinline)) int fixture_failure() {
    return 0;
}

extern "C" __attribute__((
    annotate("obf: sensitive(region=fixture-auth,strict=1), vm(preset=max)"),
    noinline)) int
fixture_decision(const unsigned char *payload, unsigned long size,
                 const char *actual, const char *expected) {
    fixture_transport(payload, size);
    if (!fixture_verify(payload, size)) {
        return fixture_failure();
    }
    if (fixture_compare(actual, expected) != 0) {
        return fixture_failure();
    }
    return fixture_success();
}

extern "C" __attribute__((used, section(".text.fixture_zero_cave"), aligned(16)))
const unsigned char fixture_zero_cave[1024] = {};
