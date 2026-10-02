#include "../cloud_value_manager.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <openssl/hmac.h>

using namespace xollvm;

static const uint64_t TEST_MASK = VM_DISPATCH_OFFSET_MASK;
static int g_failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        ++g_failures; \
    } \
} while (0)

static uint64_t hmac64_raw(const uint8_t* key, size_t key_len,
                           const uint8_t* data, size_t data_len) {
    uint8_t out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
    uint64_t r = 0;
    if (out_len >= 8) std::memcpy(&r, out, 8);
    return r;
}

// 模拟云端：暴力搜索一个 V，使 offset==0（真实云端用受控 nonce + k）
static bool findValidV(uint64_t window, uint8_t out[V_SIZE], uint64_t* tries) {
    for (uint64_t i = 0; i < (1ull << 24); ++i) {
        std::memset(out, 0, V_SIZE);
        std::memcpy(out, &i, sizeof(i));
        uint64_t raw = hmac64_raw(out, V_SIZE,
            reinterpret_cast<const uint8_t*>(&window), sizeof(window));
        if ((raw & TEST_MASK) == 0) {
            if (tries) *tries = i + 1;
            return true;
        }
    }
    return false;
}

void test_offset_range() {
    printf("[TEST] offset 取值范围...\n");
    CloudValueManager& mgr = CloudValueManager::getInstance();
    uint8_t v[V_SIZE];
    for (int i = 0; i < 256; ++i) {
        std::memset(v, i, V_SIZE);
        mgr.updateV(v, V_SIZE);
        uint64_t off = mgr.computeDispatchOffset();
        CHECK(off <= TEST_MASK);
    }
    printf("[PASS] offset 始终在 [0, MASK] 内\n\n");
}

void test_valid_v_gives_zero() {
    printf("[TEST] 合法 V → offset==0...\n");
    CloudValueManager& mgr = CloudValueManager::getInstance();
    mgr.setTimeOffset(0);
    uint64_t window = mgr.getWindowId();

    uint8_t v[V_SIZE];
    uint64_t tries = 0;
    bool found = findValidV(window, v, &tries);
    CHECK(found);
    printf("  搜索到合法 V：尝试 %llu 次\n", (unsigned long long)tries);

    mgr.updateV(v, V_SIZE);
    uint64_t off = mgr.computeDispatchOffset();
    printf("  合法 V 的 offset: %llu\n", (unsigned long long)off);
    CHECK(off == 0);

    printf("[PASS] 合法 V 得到 0\n\n");
}

void test_invalid_v_nonzero() {
    printf("[TEST] 错误 V → offset!=0（多数情况）...\n");
    CloudValueManager& mgr = CloudValueManager::getInstance();
    uint8_t v[V_SIZE];
    int nonzero = 0;
    for (int i = 1; i <= 32; ++i) {
        std::memset(v, i, V_SIZE);
        mgr.updateV(v, V_SIZE);
        if (mgr.computeDispatchOffset() != 0) ++nonzero;
    }
    printf("  32 个随机 V 中 %d 个 offset!=0\n", nonzero);
    CHECK(nonzero > 28);
    printf("[PASS] 错误 V 基本都非 0\n\n");
}

void test_window_rollover_changes_offset() {
    printf("[TEST] 窗口推进导致 offset 变化（过期失效）...\n");
    CloudValueManager& mgr = CloudValueManager::getInstance();
    mgr.setTimeOffset(0);
    uint64_t window = mgr.getWindowId();

    uint8_t v[V_SIZE];
    CHECK(findValidV(window, v, nullptr));
    mgr.updateV(v, V_SIZE);
    CHECK(mgr.computeDispatchOffset() == 0);

    mgr.setTimeOffset(VM_DISPATCH_WINDOW_SEC);
    uint64_t off = mgr.computeDispatchOffset();
    printf("  新窗口下旧 V 的 offset: %llu\n", (unsigned long long)off);
    CHECK(off != 0);

    mgr.setTimeOffset(0);
    printf("[PASS] 窗口推进使旧 V 失效\n\n");
}

void test_c_interface() {
    printf("[TEST] C 接口 __zone_get_dispatch_offset...\n");
    uint64_t off = __zone_get_dispatch_offset();
    printf("  offset: %llu\n", (unsigned long long)off);
    CHECK(off <= TEST_MASK);
    printf("[PASS] C 接口\n\n");
}

int main() {
    printf("=== Cloud Value Manager 测试套件 ===\n\n");
    printf("配置: WINDOW=%u MASK=0x%llx PREFETCH=%u\n\n",
        VM_DISPATCH_WINDOW_SEC, (unsigned long long)TEST_MASK,
        VM_DISPATCH_PREFETCH_SEC);

    test_offset_range();
    test_valid_v_gives_zero();
    test_invalid_v_nonzero();
    test_window_rollover_changes_offset();
    test_c_interface();

    if (g_failures == 0) {
        printf("=== 所有测试通过 ===\n");
        return 0;
    }
    printf("=== %d 项断言失败 ===\n", g_failures);
    return 1;
}
