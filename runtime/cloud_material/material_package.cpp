#include "material_package.h"
#include <openssl/evp.h>
#include <algorithm>
#include <limits>
#include <memory>
#include <string_view>

namespace xovm::material {
namespace {
using nlohmann::json;

[[noreturn]] void fail(const char *code) { throw PackageError{code}; }

// 仅保存有界栈和 key 的输入视图，不分配字符串/数组/DOM。
class Scanner {
    std::string_view input;
    size_t pos = 0;
    size_t bcLength = 0;

    int at() const { return pos < input.size() ? static_cast<unsigned char>(input[pos]) : -1; }
    void take(int c) {
        if (at() != c) fail("invalid_canonical");
        ++pos;
    }
    std::string_view string(size_t limit, bool key = false) {
        take('"');
        const size_t start = pos;
        size_t count = 0;
        while (pos < input.size() && at() != '"') {
            if (++count > limit) fail("string_limit");
            int c = at();
            ++pos;
            if (c < 32 || c > 126) fail("invalid_ascii");
            if (c == '\\') {
                c = at();
                ++pos;
                if (key || (c != '"' && c != '\\')) fail("invalid_canonical");
            }
        }
        const size_t end = pos;
        take('"');
        return input.substr(start, end - start);
    }
    static bool validKey(std::string_view key) {
        if (key.empty() || key.front() < 'a' || key.front() > 'z') return false;
        return std::all_of(key.begin(), key.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        });
    }
    void value(unsigned depth, bool large = false) {
        const int c = at();
        if (c == '{' || c == '[') {
            if (depth > 8) fail("depth_limit");
            ++pos;
            const bool object = c == '{';
            const int close = object ? '}' : ']';
            size_t count = 0;
            std::string_view previous;
            if (at() == close) { ++pos; return; }
            while (true) {
                if (++count > (object ? 40u : 256u)) fail(object ? "object_limit" : "array_limit");
                std::string_view key;
                if (object) {
                    key = string(64, true);
                    if (!validKey(key) || key <= previous) fail("invalid_key_order");
                    previous = key;
                    take(':');
                }
                value(depth + 1, object && depth == 1 && key == "encoded_bc");
                if (at() == close) { ++pos; break; }
                take(',');
            }
        } else if (c == '"') {
            auto text = string(large ? kMaxBase64 : 256);
            if (large) {
                bcLength = text.size();
                if (bcLength > kMaxBase64) fail("string_limit");
            }
        } else if (c >= '0' && c <= '9') {
            const size_t start = pos;
            uint64_t n = 0;
            while (at() >= '0' && at() <= '9') {
                if (pos - start == 10) fail("number_limit");
                n = n * 10 + at() - '0';
                ++pos;
            }
            if (pos - start > 1 && c == '0') fail("invalid_canonical");
            if (n > UINT32_MAX) fail("invalid_u32");
        } else {
            const std::string_view word = c == 't' ? "true" : c == 'f' ? "false" : "";
            if (word.empty()) fail("invalid_canonical");
            for (char ch : word) take(ch);
        }
    }
public:
    explicit Scanner(std::span<const uint8_t> bytes)
        : input(reinterpret_cast<const char *>(bytes.data()), bytes.size()) {}
    void scan() {
        if (input.size() > kMaxPlaintext) fail("size_limit");
        value(1);
        if (pos != input.size()) fail("invalid_canonical");
        if (input.size() - bcLength > kMaxOverhead) fail("overhead_limit");
    }
};

void closed(const json &value, std::initializer_list<const char *> fields) {
    if (!value.is_object() || value.size() != fields.size()) fail("invalid_schema");
    for (const char *field : fields) if (!value.contains(field)) fail("invalid_schema");
}

uint32_t u32(const json &value, uint32_t min = 0, uint32_t max = UINT32_MAX) {
    if (!value.is_number_unsigned()) fail("invalid_u32");
    auto n = value.get<uint64_t>();
    if (n < min || n > max) fail("invalid_u32");
    return static_cast<uint32_t>(n);
}

const std::string &text(const json &value) {
    if (!value.is_string()) fail("invalid_type");
    return value.get_ref<const std::string &>();
}

uint64_t u64(const json &value) {
    const auto &s = text(value);
    if (s.empty() || s.size() > 20 || (s.size() > 1 && s.front() == '0')) fail("invalid_u64");
    uint64_t n = 0;
    for (char c : s) {
        if (c < '0' || c > '9') fail("invalid_u64");
        const auto digit = static_cast<uint64_t>(c - '0');
        if (n > (UINT64_MAX - digit) / 10) fail("u64_overflow");
        n = n * 10 + digit;
    }
    return n;
}

void checkHash(std::string_view s) {
    if (s.size() != 64 || !std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    })) fail("invalid_hash");
}

void checkBinding(const MaterialBinding &b) {
    for (const auto *s : {&b.build_id, &b.region_id, &b.session_id, &b.request_hash,
                          &b.engine_abi_hash, &b.package_hash}) checkHash(*s);
    if (b.session_id == std::string(64, '0')) fail("invalid_session");
    if (!b.generation) fail("invalid_generation");
    if (b.mode != "session" && b.mode != "lease") fail("invalid_mode");
    if ((b.mode == "session" && b.lease_ms != 0) ||
        (b.mode == "lease" && (b.lease_ms == 0 || b.lease_ms > 120000))) fail("invalid_u32");
}

MaterialBinding bindingImpl(const json &value) {
    closed(value, {"build_id", "region_id", "session_id", "generation", "request_hash",
                   "mode", "lease_ms", "engine_abi_hash", "package_hash"});
    MaterialBinding b{text(value.at("build_id")), text(value.at("region_id")),
                      text(value.at("session_id")), u64(value.at("generation")),
                      text(value.at("request_hash")), text(value.at("mode")),
                      u32(value.at("lease_ms")), text(value.at("engine_abi_hash")),
                      text(value.at("package_hash"))};
    checkBinding(b);
    return b;
}

int b64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<uint8_t> bytecode(const std::string &s, size_t size) {
    if (s.empty() || s.size() > kMaxBase64 || s.size() % 4) fail("invalid_base64");
    const size_t padding = s.ends_with("==") ? 2 : s.ends_with("=") ? 1 : 0;
    const size_t end = s.size() - padding;
    for (size_t i = 0; i < end; ++i) if (b64Value(s[i]) < 0) fail("invalid_base64");
    if ((padding == 2 && (b64Value(s[end - 1]) & 15)) ||
        (padding == 1 && (b64Value(s[end - 1]) & 3))) fail("invalid_base64");
    // 编码长度已受限，乘法不溢出；先检查 padding 位和解码尺寸再分配。
    if (3 * (s.size() / 4) - padding != size) fail("bytecode_size_mismatch");
    std::vector<uint8_t> result(size);
    size_t out = 0;
    uint32_t bits = 0;
    unsigned count = 0;
    for (size_t i = 0; i < end; ++i) {
        bits = (bits << 6) | static_cast<uint32_t>(b64Value(s[i]));
        count += 6;
        if (count >= 8) {
            count -= 8;
            result[out++] = static_cast<uint8_t>(bits >> count);
        }
    }
    return result;
}

std::string packageHash(json &package) {
    // 仅删除 binding 的直接 package_hash；其他成员逐字节进入前像。
    package.at("binding").erase("package_hash");
    const auto core = package.dump();
    const uint32_t n = static_cast<uint32_t>(core.size());
    const uint8_t length[] = {static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
                              static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
    constexpr char label[] = "XOVM2/package";
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    uint8_t hash[32];
    unsigned int hashSize = 0;
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), label, sizeof(label)) != 1 ||
        EVP_DigestUpdate(ctx.get(), length, sizeof(length)) != 1 ||
        EVP_DigestUpdate(ctx.get(), core.data(), core.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), hash, &hashSize) != 1 || hashSize != 32) fail("hash_failure");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (auto b : hash) {
        result += hex[b >> 4];
        result += hex[b & 15];
    }
    return result;
}

template<class T, class F> ParseResult<T> guarded(F f) {
    try {
        return f();
    } catch (const PackageError &error) {
        return error;
    } catch (const std::bad_alloc &) {
        return PackageError{"allocation_failed"};
    } catch (const json::exception &) {
        return PackageError{"invalid_schema"};
    }
}
} // namespace

ParseResult<json> decodeCanonical(std::span<const uint8_t> bytes) {
    return guarded<json>([&] {
        Scanner(bytes).scan();
        // 现有 nlohmann 版本依赖 char_traits；新 libc++ 不提供 unsigned char 特化。
        const auto *begin = reinterpret_cast<const char *>(bytes.data());
        auto value = json::parse(begin, begin + bytes.size());
        const auto canonical = value.dump();
        if (canonical.size() != bytes.size() ||
            !std::equal(canonical.begin(), canonical.end(), bytes.begin())) fail("invalid_canonical");
        return value;
    });
}

ParseResult<MaterialBinding> parseMaterialBinding(const json &value) {
    return guarded<MaterialBinding>([&] { return bindingImpl(value); });
}

ParseResult<ParsedPackage> parseExecutionPackage(std::span<const uint8_t> bytes,
                                                const MaterialBinding &expectedBinding) {
    return guarded<ParsedPackage>([&] {
        auto decoded = decodeCanonical(bytes);
        if (auto *error = std::get_if<PackageError>(&decoded)) throw *error;
        auto p = std::move(std::get<json>(decoded));
        closed(p, {"format_version", "binding", "bytecode_size", "encoded_bc",
                   "decode_map", "static_decode_descriptor"});
        u32(p.at("format_version"), 1, 1);
        ParsedPackage result;
        result.binding = bindingImpl(p.at("binding"));
        checkBinding(expectedBinding);
        const auto size = u32(p.at("bytecode_size"), 1, kMaxBytecode);
        const auto &d = p.at("static_decode_descriptor");
        closed(d, {"decode_salt", "isa_version", "layout_hash", "operand_encoding_hash"});
        result.static_decode_descriptor = {u32(d.at("decode_salt")), u32(d.at("isa_version"), 1, 1),
                                           text(d.at("layout_hash")), text(d.at("operand_encoding_hash"))};
        checkHash(result.static_decode_descriptor.layout_hash);
        checkHash(result.static_decode_descriptor.operand_encoding_hash);
        const auto &map = p.at("decode_map");
        if (!map.is_array() || map.size() != 256) fail("invalid_map");
        std::array<bool, 256> seen{};
        size_t used = 0;
        for (size_t i = 0; i < 256; ++i) {
            const auto op = u32(map[i], 0, 65535);
            if (op != 65535) {
                if (op > 255 || seen[op]) fail("invalid_map");
                seen[op] = true;
                ++used;
            }
            result.decode_map[i] = static_cast<uint16_t>(op);
        }
        if (!used) fail("invalid_map");
        result.bytecode = bytecode(text(p.at("encoded_bc")), size);
        if (packageHash(p) != result.binding.package_hash) fail("package_hash_mismatch");
        if (result.binding != expectedBinding) fail("binding_mismatch");
        return result;
    });
}
} // namespace xovm::material
