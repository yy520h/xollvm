#include "ecc_window_client.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace xovm {
namespace material {

ECCWindowClient::ECCWindowClient(const std::string& server_pubkey_hex)
    : curve_nid_(NID_secp256k1)
    , group_(nullptr)
    , server_pubkey_(nullptr)
    , ephemeral_key_(nullptr) {

    // 初始化椭圆曲线群
    group_ = EC_GROUP_new_by_curve_name(curve_nid_);
    if (!group_) {
        return;
    }

    // 解析服务器公钥
    server_pubkey_ = EC_POINT_hex2point(group_, server_pubkey_hex.c_str(),
                                       nullptr, nullptr);
    if (!server_pubkey_) {
        EC_GROUP_free(group_);
        group_ = nullptr;
        return;
    }

    // 初始化临时密钥（将在第一次 generateEphemeralKey 时生成）
    ephemeral_key_ = EC_KEY_new_by_curve_name(curve_nid_);
}

ECCWindowClient::~ECCWindowClient() {
    if (ephemeral_key_) {
        EC_KEY_free(ephemeral_key_);
    }
    if (server_pubkey_) {
        EC_POINT_free(server_pubkey_);
    }
    if (group_) {
        EC_GROUP_free(group_);
    }
}

std::string ECCWindowClient::generateEphemeralKey() {
    if (!ephemeral_key_ || !group_) {
        return "";
    }

    // 生成新的临时密钥对
    if (EC_KEY_generate_key(ephemeral_key_) != 1) {
        return "";
    }

    // 导出临时公钥（压缩格式）
    const EC_POINT* pub_point = EC_KEY_get0_public_key(ephemeral_key_);
    char* pub_hex = EC_POINT_point2hex(group_, pub_point,
                                      POINT_CONVERSION_COMPRESSED,
                                      nullptr);

    current_ephemeral_pubkey_hex_ = pub_hex;
    OPENSSL_free(pub_hex);

    return current_ephemeral_pubkey_hex_;
}

std::vector<uint8_t> ECCWindowClient::decryptWindow(const std::vector<uint8_t>& encrypted) {
    std::vector<uint8_t> decrypted;

    if (!ephemeral_key_ || !server_pubkey_ || !group_) {
        return decrypted;
    }

    // 计算共享密钥
    auto shared_secret = computeSharedSecret();

    // XOR 解密
    decrypted.resize(encrypted.size());
    for (size_t i = 0; i < encrypted.size(); i++) {
        decrypted[i] = encrypted[i] ^ shared_secret[i % 32];
    }

    return decrypted;
}

std::string ECCWindowClient::getCurrentEphemeralPublicKey() const {
    return current_ephemeral_pubkey_hex_;
}

std::array<uint8_t, 32> ECCWindowClient::computeSharedSecret() {
    std::array<uint8_t, 32> secret = {0};

    if (!ephemeral_key_ || !server_pubkey_ || !group_) {
        return secret;
    }

    // 计算共享点: S = d_ephemeral * Q_server
    EC_POINT* shared_point = EC_POINT_new(group_);
    const BIGNUM* ephemeral_priv = EC_KEY_get0_private_key(ephemeral_key_);

    if (EC_POINT_mul(group_, shared_point, nullptr, server_pubkey_,
                    ephemeral_priv, nullptr) != 1) {
        EC_POINT_free(shared_point);
        return secret;
    }

    // 提取共享点的 x 坐标
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group_, shared_point, x, y, nullptr);

    // 将 x 坐标转换为字节数组
    unsigned char x_bytes[32];
    int len = BN_num_bytes(x);
    BN_bn2bin(x, x_bytes);

    // SHA256 派生最终共享密钥
    SHA256(x_bytes, len, secret.data());

    // 清理
    BN_free(x);
    BN_free(y);
    EC_POINT_free(shared_point);

    return secret;
}

std::vector<uint8_t> ECCWindowClient::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string ECCWindowClient::bytesToHex(const uint8_t* bytes, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

} // namespace material
} // namespace xovm
