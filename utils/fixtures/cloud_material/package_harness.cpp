#include "runtime/cloud_material/material_abi.h"
#include "runtime/cloud_material/material_package.h"
#include <openssl/sha.h>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <new>
#include <thread>

using namespace xovm::material;
using nlohmann::json;

// 仅 fixture 替换分配器：输入缓冲已读入后禁用分配，检测是否提前建 DOM。
static bool denyAllocation = false;
void *operator new(size_t size) {
    if (denyAllocation) throw std::bad_alloc();
    if (void *p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void *p) noexcept { std::free(p); }
void *operator new[](size_t size) { return ::operator new(size); }
void operator delete[](void *p) noexcept { ::operator delete(p); }

static void reject(const char *code) {
    std::cout << json{{"ok", false}, {"code", code}}.dump() << '\n';
}

static std::string digest(std::span<const uint8_t> data) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    const char *hex = "0123456789abcdef";
    std::string result;
    for (auto b : hash) {
        result += hex[b >> 4];
        result += hex[b & 15];
    }
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const std::string name = argv[1];
    if (name == "fail") {
        std::cerr << "fixture_failure\n";
        return 7;
    }
    if (name == "wait") {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 0;
    }
    if (name == "abi") {
        std::cout << json{{"ok", true}, {"descriptor_size", sizeof(XovmRegionDescriptor)},
                          {"record_size", sizeof(XovmMaterialRecord)},
                          {"view_size", sizeof(XovmMaterialView)}}.dump() << '\n';
        return 0;
    }
    if (name != "package" && name != "canonical" && name != "canonical-noalloc") return 2;
    std::string expected;
    char ch;
    while (std::cin.get(ch) && ch != '\n') {
        if (expected.size() == 2048) { reject("size_limit"); return 0; }
        expected += ch;
    }
    std::vector<uint8_t> input;
    char buffer[4096];
    while (std::cin) {
        std::cin.read(buffer, sizeof(buffer));
        const auto count = static_cast<size_t>(std::cin.gcount());
        if (input.size() + count > kMaxPlaintext) { reject("size_limit"); return 0; }
        input.insert(input.end(), buffer, buffer + count);
    }
    if (name == "canonical" || name == "canonical-noalloc") {
        denyAllocation = name == "canonical-noalloc";
        const auto result = decodeCanonical(input);
        denyAllocation = false;
        if (const auto *error = std::get_if<PackageError>(&result)) reject(error->code.c_str());
        else std::cout << "{\"ok\":true}\n";
        return 0;
    }
    auto decoded = decodeCanonical(std::span(reinterpret_cast<const uint8_t *>(expected.data()), expected.size()));
    if (const auto *error = std::get_if<PackageError>(&decoded)) { reject(error->code.c_str()); return 0; }
    auto binding = parseMaterialBinding(std::get<json>(decoded));
    if (const auto *error = std::get_if<PackageError>(&binding)) { reject(error->code.c_str()); return 0; }
    auto result = parseExecutionPackage(input, std::get<MaterialBinding>(binding));
    if (const auto *error = std::get_if<PackageError>(&result)) {
        reject(error->code.c_str());
    } else {
        const auto &p = std::get<ParsedPackage>(result);
        std::cout << json{{"ok", true}, {"bytecode_size", p.bytecode.size()},
                          {"generation", std::to_string(p.binding.generation)},
                          {"package_hash", p.binding.package_hash},
                          {"bytecode_hash", digest(p.bytecode)}}.dump() << '\n';
    }
}
