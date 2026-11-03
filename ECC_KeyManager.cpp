// ============================================================================
// ECC_KeyManager.cpp - 椭圆曲线密钥管理实现
// ============================================================================

#include "llvm/Transforms/Obfuscator/ECC_KeyManager.h"
#include "llvm/Support/raw_ostream.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>

using namespace llvm;

// ============================================================================
// ECCKeyPair 实现
// ============================================================================

ECCKeyPair::ECCKeyPair() : key_(nullptr), group_(nullptr) {
    // 使用 secp256k1 曲线（比特币使用的曲线，性能好）
    key_ = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (key_) {
        group_ = EC_KEY_get0_group(key_);
    }
}

ECCKeyPair::~ECCKeyPair() {
    if (key_) {
        EC_KEY_free(key_);
    }
}

bool ECCKeyPair::generate() {
    if (!key_) return false;

    // 生成密钥对
    if (EC_KEY_generate_key(key_) != 1) {
        return false;
    }

    // 验证密钥
    if (EC_KEY_check_key(key_) != 1) {
        return false;
    }

    return true;
}

std::string ECCKeyPair::exportPrivateKeyHex() const {
    if (!key_) return "";

    const BIGNUM* priv_bn = EC_KEY_get0_private_key(key_);
    if (!priv_bn) return "";

    char* hex = BN_bn2hex(priv_bn);
    std::string result(hex);
    OPENSSL_free(hex);

    return result;
}

std::string ECCKeyPair::exportPublicKeyHex() const {
    if (!key_ || !group_) return "";

    const EC_POINT* pub_point = EC_KEY_get0_public_key(key_);
    if (!pub_point) return "";

    // 使用压缩格式（33 字节）
    char* hex = EC_POINT_point2hex(group_, pub_point,
                                   POINT_CONVERSION_COMPRESSED,
                                   nullptr);
    std::string result(hex);
    OPENSSL_free(hex);

    return result;
}

bool ECCKeyPair::exportPublicKeyCoordinates(std::string& x_hex, std::string& y_hex) const {
    if (!key_ || !group_) return false;

    const EC_POINT* pub_point = EC_KEY_get0_public_key(key_);
    if (!pub_point) return false;

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    if (EC_POINT_get_affine_coordinates(group_, pub_point, x, y, nullptr) != 1) {
        BN_free(x);
        BN_free(y);
        return false;
    }

    char* x_str = BN_bn2hex(x);
    char* y_str = BN_bn2hex(y);

    x_hex = x_str;
    y_hex = y_str;

    OPENSSL_free(x_str);
    OPENSSL_free(y_str);
    BN_free(x);
    BN_free(y);

    return true;
}

bool ECCKeyPair::importPrivateKeyHex(const std::string& hex) {
    if (!key_) return false;

    BIGNUM* priv_bn = nullptr;
    if (BN_hex2bn(&priv_bn, hex.c_str()) == 0) {
        return false;
    }

    if (EC_KEY_set_private_key(key_, priv_bn) != 1) {
        BN_free(priv_bn);
        return false;
    }

    // 从私钥计算公钥
    EC_POINT* pub_point = EC_POINT_new(group_);
    if (EC_POINT_mul(group_, pub_point, priv_bn, nullptr, nullptr, nullptr) != 1) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        return false;
    }

    EC_KEY_set_public_key(key_, pub_point);

    EC_POINT_free(pub_point);
    BN_free(priv_bn);

    return true;
}

bool ECCKeyPair::importPublicKeyHex(const std::string& hex) {
    if (!key_ || !group_) return false;

    EC_POINT* pub_point = EC_POINT_hex2point(group_, hex.c_str(), nullptr, nullptr);
    if (!pub_point) return false;

    if (EC_KEY_set_public_key(key_, pub_point) != 1) {
        EC_POINT_free(pub_point);
        return false;
    }

    EC_POINT_free(pub_point);
    return true;
}

std::array<uint8_t, 32> ECCKeyPair::computeSharedSecret(const std::string& peer_pubkey_hex) const {
    std::array<uint8_t, 32> secret = {0};

    if (!key_ || !group_) return secret;

    // 解析对方公钥
    EC_POINT* peer_point = EC_POINT_hex2point(group_, peer_pubkey_hex.c_str(),
                                              nullptr, nullptr);
    if (!peer_point) return secret;

    // 计算共享点 S = d·Q（私钥 * 对方公钥）
    EC_POINT* shared_point = EC_POINT_new(group_);
    const BIGNUM* priv_key = EC_KEY_get0_private_key(key_);

    if (EC_POINT_mul(group_, shared_point, nullptr, peer_point, priv_key, nullptr) != 1) {
        EC_POINT_free(shared_point);
        EC_POINT_free(peer_point);
        return secret;
    }

    // 提取 x 坐标
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group_, shared_point, x, y, nullptr);

    // 将 x 坐标转换为字节数组
    unsigned char x_bytes[32];
    int len = BN_num_bytes(x);
    BN_bn2bin(x, x_bytes);

    // SHA256 派生最终密钥
    SHA256(x_bytes, len, secret.data());

    // 清理
    BN_free(x);
    BN_free(y);
    EC_POINT_free(shared_point);
    EC_POINT_free(peer_point);

    return secret;
}

// ============================================================================
// ECCKeyManager 实现
// ============================================================================

ECCKeyManager::ECCKeyManager() {
}

bool ECCKeyManager::generateKeys() {
    outs() << "[ECC] Generating elliptic curve key pair (secp256k1)...\n";

    if (!server_key_.generate()) {
        errs() << "[ECC] Failed to generate key pair\n";
        return false;
    }

    outs() << "[ECC] Key pair generated successfully\n";
    return true;
}

bool ECCKeyManager::saveServerPrivateKey(const std::string& config_path) const {
    std::string priv_hex = server_key_.exportPrivateKeyHex();
    if (priv_hex.empty()) {
        errs() << "[ECC] Failed to export private key\n";
        return false;
    }

    // 读取现有配置
    std::ifstream infile(config_path);
    std::stringstream buffer;
    if (infile.is_open()) {
        buffer << infile.rdbuf();
        infile.close();
    }

    // 在 storage 部分之后添加 encryption 配置
    std::string config = buffer.str();

    std::ostringstream new_section;
    new_section << "\n# 窗口加密配置（ECC 动态加密）\n";
    new_section << "encryption:\n";
    new_section << "  enabled: true\n";
    new_section << "  algorithm: \"ECDH-secp256k1\"\n";
    new_section << "  server_private_key: \"" << priv_hex << "\"\n";
    new_section << "  # 私钥长度: " << priv_hex.length() << " 字符\n";
    new_section << "  # 警告: 私钥泄露将导致所有窗口可被解密\n";

    // 写入配置文件
    std::ofstream outfile(config_path, std::ios::app);
    if (!outfile.is_open()) {
        errs() << "[ECC] Failed to open config file: " << config_path << "\n";
        return false;
    }

    outfile << new_section.str();
    outfile.close();

    outs() << "[ECC] Server private key saved to: " << config_path << "\n";
    outs() << "[ECC] Private key (first 16 chars): " << priv_hex.substr(0, 16) << "...\n";

    return true;
}

bool ECCKeyManager::generateClientConfigHeader(const std::string& output_path) const {
    std::string pub_hex = server_key_.exportPublicKeyHex();
    if (pub_hex.empty()) {
        errs() << "[ECC] Failed to export public key\n";
        return false;
    }

    std::string x_hex, y_hex;
    if (!server_key_.exportPublicKeyCoordinates(x_hex, y_hex)) {
        errs() << "[ECC] Failed to export public key coordinates\n";
        return false;
    }

    std::ofstream header(output_path);
    if (!header.is_open()) {
        errs() << "[ECC] Failed to create header file: " << output_path << "\n";
        return false;
    }

    header << "// Auto-generated by xollvm CloudMaterial ECC\n";
    header << "// DO NOT EDIT MANUALLY\n\n";
    header << "#ifndef XOLLVM_ECC_CONFIG_H\n";
    header << "#define XOLLVM_ECC_CONFIG_H\n\n";
    header << "#include <string>\n\n";
    header << "namespace xovm {\n";
    header << "namespace material {\n";
    header << "namespace ecc {\n\n";
    header << "// ECC 窗口加密配置\n";
    header << "// 使用 secp256k1 椭圆曲线（比特币使用的曲线）\n\n";
    header << "// 服务器公钥（压缩格式，33 字节）\n";
    header << "constexpr const char* SERVER_PUBLIC_KEY_HEX = \"" << pub_hex << "\";\n\n";
    header << "// 服务器公钥坐标（用于验证）\n";
    header << "constexpr const char* SERVER_PUBLIC_KEY_X = \"" << x_hex << "\";\n";
    header << "constexpr const char* SERVER_PUBLIC_KEY_Y = \"" << y_hex << "\";\n\n";
    header << "// 椭圆曲线参数\n";
    header << "constexpr const char* CURVE_NAME = \"secp256k1\";\n";
    header << "constexpr int CURVE_NID = 714;  // NID_secp256k1\n\n";
    header << "// 安全参数\n";
    header << "constexpr int SHARED_SECRET_SIZE = 32;  // SHA256 输出\n";
    header << "constexpr bool ENABLE_ENCRYPTION = true;\n\n";
    header << "} // namespace ecc\n";
    header << "} // namespace material\n";
    header << "} // namespace xovm\n\n";
    header << "#endif // XOLLVM_ECC_CONFIG_H\n";

    header.close();

    outs() << "[ECC] Client config header generated: " << output_path << "\n";
    outs() << "[ECC] Public key (first 16 chars): " << pub_hex.substr(0, 16) << "...\n";

    return true;
}

std::string ECCKeyManager::getKeyInfo() const {
    std::ostringstream info;

    info << "ECC Key Information:\n";
    info << "  Curve: secp256k1\n";
    info << "  Key size: 256 bits\n";

    std::string priv_hex = server_key_.exportPrivateKeyHex();
    std::string pub_hex = server_key_.exportPublicKeyHex();

    info << "  Private key length: " << priv_hex.length() << " hex chars\n";
    info << "  Public key length: " << pub_hex.length() << " hex chars\n";
    info << "  Private key (first 16): " << priv_hex.substr(0, 16) << "...\n";
    info << "  Public key (first 16): " << pub_hex.substr(0, 16) << "...\n";

    return info.str();
}
