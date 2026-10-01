#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <ctime>
#include <algorithm>
#include <memory>

namespace DES {

namespace detail {
    inline std::vector<bool> toBinary(const std::vector<uint8_t>& bytes) {
        std::vector<bool> bits(bytes.size() * 8);
        for (size_t i = 0; i < bytes.size(); ++i)
            for (int j = 7; j >= 0; --j)
                bits[i * 8 + (7 - j)] = (bytes[i] >> j) & 1;
        return bits;
    }
    inline std::vector<uint8_t> toAscii(const std::vector<bool>& bits) {
        if (bits.empty() || bits.size() % 8 != 0) return {};
        std::vector<uint8_t> bytes(bits.size() / 8);
        for (size_t i = 0; i < bits.size(); i += 8) {
            uint8_t c = 0;
            for (int j = 0; j < 8; ++j)
                c = (c << 1) | bits[i + j];
            bytes[i / 8] = c;
        }
        return bytes;
    }
    inline std::vector<uint8_t> toByteVector(const std::string& s) {
        return std::vector<uint8_t>(s.begin(), s.end());
    }
    inline std::vector<bool> toBitVector(const std::string& s) {
        return toBinary(toByteVector(s));
    }
    inline std::vector<uint8_t> binToHex(const std::vector<bool>& bits) {
        if (bits.empty() || bits.size() % 4 != 0) return {};
        std::vector<uint8_t> hex;
        for (size_t i = 0; i < bits.size(); i += 4) {
            uint8_t val = 0;
            for (int j = 0; j < 4; ++j)
                val = (val << 1) | bits[i + j];
            hex.push_back(val < 10 ? '0' + val : 'A' + (val - 10));
        }
        return hex;
    }
    inline std::string hexStr(const std::vector<uint8_t>& hex) {
        return std::string(hex.begin(), hex.end());
    }
    inline std::string toBase64(const std::vector<uint8_t>& data) {
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        size_t i = 0;
        for (; i + 2 < data.size(); i += 3) {
            out += b64[(data[i] >> 2) & 0x3F];
            out += b64[((data[i] & 0x3) << 4) | ((data[i + 1] >> 4) & 0x0F)];
            out += b64[((data[i + 1] & 0x0F) << 2) | ((data[i + 2] >> 6) & 0x03)];
            out += b64[data[i + 2] & 0x3F];
        }
        if (i < data.size()) {
            out += b64[(data[i] >> 2) & 0x3F];
            if (i + 1 < data.size()) {
                out += b64[((data[i] & 0x3) << 4) | ((data[i + 1] >> 4) & 0x0F)];
                out += b64[(data[i + 1] & 0x0F) << 2];
                out += '=';
            } else {
                out += b64[(data[i] & 0x3) << 4];
                out += "==";
            }
        }
        return out;
    }
}

class EncryptedResult {
public:
    using BitVec = std::vector<bool>;
    explicit EncryptedResult(BitVec data) : bits_(std::move(data)) {}
    std::string toString() const {
        auto bytes = detail::toAscii(bits_);
        return std::string(bytes.begin(), bytes.end());
    }
    std::string toHex() const {
        auto hex = detail::binToHex(bits_);
        return detail::hexStr(hex);
    }
    std::string toBase64() const {
        auto bytes = detail::toAscii(bits_);
        return detail::toBase64(bytes);
    }
    std::string toBitString() const {
        std::string s;
        s.reserve(bits_.size());
        for (bool b : bits_) s += (b ? '1' : '0');
        return s;
    }
    std::vector<bool> toVector() const { return bits_; }
private:
    BitVec bits_;
};

class DES {
public:
    using BitVec = std::vector<bool>;
    explicit DES(const std::string& key) { setKey(key); }
    void setKey(const std::string& key) {
        keyBits_ = _convertKeyStr2Binary(key.size() > 8 ? key.substr(0, 8) : key);
        _initObjectState();
        _generateSubkeys(keyBits_);
    }
    BitVec encrypt(const BitVec& data, bool pad = true) const {
        BitVec source(data);
        if (pad) _PKCS7Padding(source);
        BitVec out;
        for (size_t i = 0; i < source.size(); i += _KeySize) {
            BitVec block(source.begin() + i, source.begin() + i + _KeySize);
            BitVec encryptedBlock(_KeySize);
            _64bitBlockETransformation(block, encryptedBlock);
            out.insert(out.end(), encryptedBlock.begin(), encryptedBlock.end());
        }
        return out;
    }
    BitVec encrypt(const std::string& data) const {
        return encrypt(detail::toBitVector(data));
    }
    BitVec decrypt(const BitVec& data, bool unpad = true) const {
        BitVec source(data);
        BitVec out;
        for (size_t i = 0; i < source.size(); i += _KeySize) {
            BitVec block(source.begin() + i, source.begin() + i + _KeySize);
            BitVec decryptedBlock(_KeySize);
            _64bitBlockDTransformation(block, decryptedBlock);
            out.insert(out.end(), decryptedBlock.begin(), decryptedBlock.end());
        }
        if (unpad) _PKCS7RemovePadding(out);
        return out;
    }
    BitVec decrypt(const std::string& data) const {
        return decrypt(detail::toBitVector(data));
    }
    EncryptedResult Encrypt(const std::string& data) const { return EncryptedResult(encrypt(data)); }
    EncryptedResult Encrypt(const BitVec& data) const { return EncryptedResult(encrypt(data)); }
    EncryptedResult Decrypt(const std::string& data) const { return EncryptedResult(decrypt(data)); }
    EncryptedResult Decrypt(const BitVec& data) const { return EncryptedResult(decrypt(data)); }
    void _PKCS7Padding(BitVec& source) const {
        if (source.empty()) return;
        uint8_t padv = static_cast<uint8_t>(_KeySize - (source.size() % _KeySize));
        uint8_t padding_size = padv == _KeySize ? static_cast<uint8_t>(_KeySize) : padv;
        for (uint8_t i = 0; i < padding_size; ++i)
            source.push_back(static_cast<uint8_t>(padding_size));
    }
    void _PKCS7RemovePadding(BitVec& source) const {
        if (source.empty()) return;
        std::vector<uint8_t> to_string_bytes(detail::toAscii(source));
        if(to_string_bytes.empty()) return;
        const uint8_t back = to_string_bytes.back();
        while (!to_string_bytes.empty() && static_cast<int>(to_string_bytes.back()) == back) {
            to_string_bytes.pop_back();
        }
        source = detail::toBinary(to_string_bytes);
    }
private:
    using BitMatrix = std::vector<std::vector<bool>>;
    struct Halves {
        BitVec l, r;
        Halves(uint16_t s) : l(s), r(s) {}
        Halves(const Halves& other) : l(other.l), r(other.r) {}
    };
    mutable BitMatrix subkeys_;
    BitVec keyBits_;
    mutable uint32_t id_ = 0;
    static constexpr uint16_t _Rounds = 16;
    static constexpr uint16_t _KeySize = 64;
    static constexpr uint16_t _ParityBits = 8;
    static constexpr uint16_t _KeyBits = _KeySize - _ParityBits;
    static constexpr uint16_t _BlockSize = 64;
    static constexpr uint16_t _SKSize = 48;
    static constexpr uint16_t _HISize = 32;
    static constexpr uint16_t _HKSize = 28;
    static constexpr uint16_t _S_BOX[8][4][16] = {
        {{0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7},
         {0x0,0xF,0x7,0x4,0xE,0x2,0xD,0x1,0xA,0x6,0xC,0xB,0x9,0x5,0x3,0x8},
         {0x4,0x1,0xE,0x8,0xD,0x6,0x2,0xB,0xF,0xC,0x9,0x7,0x3,0xA,0x5,0x0},
         {0xF,0x2,0x8,0xE,0x6,0xB,0x1,0x3,0x4,0x9,0x7,0xD,0xA,0x0,0x5,0xC}},
        {{0xF,0x1,0x8,0xE,0x6,0xB,0x3,0x4,0x9,0x7,0x2,0xD,0x0,0x5,0xA,0xC},
         {0x3,0xD,0x4,0x7,0xF,0x2,0x8,0xE,0xC,0x0,0x1,0xA,0x6,0x9,0xB,0x5},
         {0x0,0xE,0x7,0xB,0xA,0x4,0xD,0x1,0x5,0x8,0xC,0x6,0x9,0x3,0x2,0xF},
         {0xD,0x8,0xA,0x1,0x3,0xF,0x4,0x2,0xB,0x6,0x7,0xC,0x0,0x5,0xE,0x9}},
        {{0xA,0x0,0x9,0xE,0x6,0x3,0xF,0x5,0x1,0xD,0x2,0x8,0x4,0x7,0xC,0xB},
         {0xD,0x7,0x0,0x9,0x3,0x4,0x6,0xA,0x2,0x8,0x5,0xE,0xC,0xB,0xF,0x1},
         {0xD,0x6,0x4,0x9,0x8,0xF,0x3,0x0,0xB,0x1,0x2,0xC,0x5,0xA,0xE,0x7},
         {0x1,0xA,0xD,0x0,0x6,0x9,0x8,0x7,0x4,0xF,0xE,0x3,0xB,0x5,0x2,0xC}},
        {{0x7,0xD,0xE,0x3,0x0,0x6,0x9,0xA,0x1,0x2,0x8,0x5,0xB,0xC,0x4,0xF},
         {0xD,0x8,0xB,0x5,0x6,0xF,0x0,0x3,0x4,0x7,0x2,0xC,0x1,0xA,0xE,0x9},
         {0xA,0x6,0x9,0x0,0xC,0xB,0x7,0xD,0xF,0x1,0x3,0xE,0x5,0x2,0x4,0x8},
         {0x3,0xF,0x0,0x6,0xA,0x1,0xD,0x8,0x9,0x4,0x5,0xB,0xC,0x7,0x2,0xE}},
        {{0x2,0xC,0x4,0x1,0x7,0xA,0xB,0x6,0x9,0x5,0x3,0xE,0x0,0xF,0xD,0x8},
         {0x4,0x2,0x1,0xB,0xA,0xD,0x7,0x8,0xF,0x9,0xC,0x5,0x6,0x3,0x0,0xE},
         {0xB,0x8,0xC,0x7,0x1,0xE,0x2,0xD,0x6,0xF,0x0,0x9,0xA,0x4,0x5,0x3},
         {0xC,0x1,0xA,0xF,0x9,0x2,0x6,0x8,0x0,0xD,0x3,0x4,0xE,0x7,0x5,0xB}},
        {{0xC,0x1,0xA,0xF,0x9,0x2,0x6,0x8,0x0,0xD,0x3,0x4,0xE,0x7,0x5,0xB},
         {0xA,0xF,0x4,0x2,0x1,0x7,0x6,0xB,0xD,0x9,0x0,0xE,0x3,0x5,0xC,0x8},
         {0x9,0xE,0xF,0x5,0x2,0x8,0xC,0x3,0x7,0x0,0x4,0xA,0x1,0xD,0xB,0x6},
         {0x4,0x3,0x2,0xC,0x1,0xA,0xF,0x9,0xE,0x7,0x5,0xB,0x6,0x8,0x0,0x5}},
        {{0x4,0xB,0x2,0xE,0xF,0x0,0x8,0xD,0x3,0xC,0x9,0x7,0x5,0xA,0x6,0x1},
         {0xD,0x0,0xB,0x7,0x4,0x9,0x1,0xA,0xE,0x3,0x5,0xC,0x2,0xF,0x8,0x6},
         {0x1,0x4,0xB,0xD,0xC,0x3,0x7,0xE,0xA,0xF,0x6,0x8,0x0,0x5,0x9,0x2},
         {0x6,0x1,0x4,0xB,0xD,0xC,0x3,0x7,0xE,0xA,0xF,0x8,0x0,0x5,0x9,0x2}},
        {{0xD,0x2,0x8,0x4,0x6,0xF,0xB,0x1,0xA,0x9,0x3,0xE,0x5,0x0,0xC,0x7},
         {0x1,0xF,0xD,0x8,0xA,0x3,0x7,0x4,0xC,0x5,0x6,0xB,0x0,0xE,0x9,0x2},
         {0x7,0xB,0x4,0x1,0x9,0xC,0xE,0x2,0x0,0x6,0xA,0xD,0xF,0x3,0x5,0x8},
         {0x2,0x1,0xE,0x7,0x4,0xA,0x8,0xD,0xF,0xC,0x9,0x0,0x3,0x5,0x6,0xB}}
    };
    static constexpr uint16_t _PC1[56] = {
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
    };
    static constexpr uint16_t _PC2[48] = {
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };
    static constexpr uint16_t _SHIFTS[16] = {
        1, 1, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 1, 2, 2, 1
    };
    static constexpr uint16_t _IP[64] = {
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    };
    static constexpr uint16_t _E[48] = {
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    };
    static constexpr uint16_t _IP_INV[64] = {
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    };
    void _initObjectState() const {
        if (id_ == 0) {
            uint64_t state = std::time(nullptr);
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state = (10000000) + (state % (UINT32_MAX - 10000000 + 1));
            id_ = static_cast<uint32_t>(state);
        }
    }
    void _generateSubkeys(const BitVec& key) {
        if (key.size() != _KeySize) throw std::range_error("_key size do not match max bits allowed");
        BitVec pk(_initPermutation(key));
        _keyScheduling(pk);
    }
    void _keyScheduling(const BitVec& permuted_key) {
        Halves halves(_HKSize);
        for (uint16_t i = 0; i < _HKSize; ++i) {
            halves.l[i] = permuted_key[i];
            halves.r[i] = permuted_key[i + _HKSize];
        }
        subkeys_.clear();
        for (uint16_t r = 0; r < _Rounds; ++r) {
            _keyRotation(halves, r);
            subkeys_.push_back(_compressionPermutation(halves));
        }
    }
    void _keyRotation(Halves& halves, uint16_t round) const {
        if (round >= 16) throw std::invalid_argument("_round value is invalid!");
        uint16_t shift = _SHIFTS[round];
        std::rotate(halves.l.begin(), halves.l.begin() + shift, halves.l.end());
        std::rotate(halves.r.begin(), halves.r.begin() + shift, halves.r.end());
    }
    BitVec _initPermutation(const BitVec& key) const {
        BitVec permuted_keys(_KeyBits);
        for (uint16_t i = 0; i < _KeyBits; ++i) permuted_keys[i] = key[_PC1[i] - 1];
        return permuted_keys;
    }
    BitVec _compressionPermutation(const Halves& halves) const {
        BitVec subkey(_SKSize);
        for (uint16_t i = 0; i < _SKSize; ++i)
            subkey[i] = (_PC2[i] <= 28) ? halves.l[_PC2[i] - 1] : halves.r[_PC2[i] - 29];
        return subkey;
    }
    void _64bitBlockETransformation(const BitVec& block, BitVec& output) const {
        if (block.size() != 64) throw std::invalid_argument("block size must be multiple of 64!");
        BitVec block_permutation = _64bitBlockPermutation(block);
        Halves halves = _64bitBlockPartition(block_permutation);
        for (uint16_t r = 0; r < _Rounds; ++r) {
            BitVec expanded = _expansionPermutation(halves.r);
            BitVec mixed = _keyMixing(expanded, r);
            BitVec sBoxOut = _sBoxSubstitution(mixed);
            BitVec permuted = _pPermutation(sBoxOut);
            BitVec R1(_HISize);
            for (uint16_t i = 0; i < _HISize; ++i)
                R1[i] = halves.l[i] ^ permuted[i];
            halves.l = halves.r;
            halves.r = R1;
        }
        BitVec combined(_KeySize);
        for (uint16_t i = 0; i < _KeySize / 2; ++i) {
            combined[i] = halves.r[i];
            combined[i + (_KeySize / 2)] = halves.l[i];
        }
        output = _finalPermutation(combined);
    }
    void _64bitBlockDTransformation(const BitVec& block, BitVec& output) const {
        if (block.size() != 64) throw std::invalid_argument("block size invalid!");
        BitVec permuted_input = _64bitBlockPermutation(block);
        Halves halves = _64bitBlockPartition(permuted_input);
        for (int16_t r = _Rounds - 1; r >= 0; --r) {
            BitVec expanded = _expansionPermutation(halves.r);
            BitVec mixed = _keyMixing(expanded, r);
            BitVec sBoxOut = _sBoxSubstitution(mixed);
            BitVec permuted = _pPermutation(sBoxOut);
            BitVec R1(_HISize);
            for (uint16_t i = 0; i < _HISize; ++i)
                R1[i] = halves.l[i] ^ permuted[i];
            halves.l = halves.r;
            halves.r = R1;
        }
        BitVec combined(_KeySize);
        for (uint16_t i = 0; i < _KeySize / 2; ++i) {
            combined[i] = halves.r[i];
            combined[i + (_KeySize / 2)] = halves.l[i];
        }
        output = _finalPermutation(combined);
    }
    Halves _64bitBlockPartition(const BitVec& block) const {
        Halves halves(_HISize);
        for (uint16_t i = 0; i < _HISize; ++i) {
            halves.l[i] = block[i];
            halves.r[i] = block[i + _HISize];
        }
        return halves;
    }
    BitVec _64bitBlockPermutation(const BitVec& block) const {
        BitVec block_permutation(_KeySize);
        for (uint16_t i = 0; i < _KeySize; ++i)
            block_permutation[i] = block[_IP[i] - 1];
        return block_permutation;
    }
    BitVec _expansionPermutation(const BitVec& r) const {
        BitVec expanded(_SKSize);
        for (uint16_t i = 0; i < _SKSize; ++i)
            expanded[i] = r[_E[i] - 1];
        return expanded;
    }
    BitVec _keyMixing(const BitVec& expanded, uint16_t round) const {
        BitVec mixed(_SKSize);
        for (uint16_t i = 0; i < _SKSize; ++i)
            mixed[i] = expanded[i] ^ subkeys_[round][i];
        return mixed;
    }
    BitVec _sBoxSubstitution(const BitVec& mixed) const {
        BitVec out(_HISize);
        for (uint16_t i = 0; i < 8; ++i) {
            uint16_t row = (mixed[i * 6] << 1) | mixed[i * 6 + 5];
            uint16_t col = (mixed[i * 6 + 1] << 3) | (mixed[i * 6 + 2] << 2) | (mixed[i * 6 + 3] << 1) | mixed[i * 6 + 4];
            uint16_t sboxOut = _S_BOX[i][row][col];
            for (uint16_t j = 0; j < 4; ++j)
                out[i * 4 + j] = (sboxOut >> (3 - j)) & 1;
        }
        return out;
    }
    BitVec _pPermutation(const BitVec& input) const {
        static constexpr uint16_t P[32] = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        };
        BitVec out(_HISize);
        for (uint16_t i = 0; i < _HISize; ++i)
            out[i] = input[P[i] - 1];
        return out;
    }
    BitVec _finalPermutation(const BitVec& combined) const {
        BitVec out(_KeySize);
        for (uint16_t i = 0; i < _KeySize; ++i)
            out[i] = combined[_IP_INV[i] - 1];
        return out;
    }
    static BitVec _convertKeyStr2Binary(const std::string& key) {
        BitVec keyResult(_KeySize, 0);
        for (size_t i = 0; i < key.length() && i < 8; ++i) {
            unsigned char ch = static_cast<unsigned char>(key[i]);
            for (int j = 0; j < 8; ++j)
                keyResult[i * 8 + j] = (ch >> (7 - j)) & 1;
        }
        return keyResult;
    }
};

class TripleDES {
public:
    using BitVec = std::vector<bool>;
    TripleDES(const std::string& key1, const std::string& key2, const std::string& key3)
        : des1_(key1), des2_(key2), des3_(key3) {}
    EncryptedResult Encrypt(const std::string& data) const {
        auto bits = detail::toBitVector(data);
        des1_._PKCS7Padding(bits);
        auto s1 = des1_.encrypt(bits, false);
        auto s2 = des2_.decrypt(s1, false);
        auto s3 = des3_.encrypt(s2, false);
        return EncryptedResult(s3);
    }
    EncryptedResult Encrypt(const BitVec& data) const {
        BitVec bits = data;
        des1_._PKCS7Padding(bits);
        auto s1 = des1_.encrypt(bits, false);
        auto s2 = des2_.decrypt(s1, false);
        auto s3 = des3_.encrypt(s2, false);
        return EncryptedResult(s3);
    }
    BitVec Decrypt(const BitVec& data) const {
        auto s1 = des3_.decrypt(data, false);
        auto s2 = des2_.encrypt(s1, false);
        auto s3 = des1_.decrypt(s2, false);
        BitVec out = s3;
        des1_._PKCS7RemovePadding(out);
        return out;
    }
    BitVec Decrypt(const std::string& data) const {
        auto bits = detail::toBitVector(data);
        return Decrypt(bits);
    }
    friend struct ECB;
    friend struct CBC;
    friend struct CFB;
    friend struct OFB;
    friend struct CTR;
private:
    DES des1_, des2_, des3_;
};

struct ECB {
    static EncryptedResult Encrypt(const std::string& data, const std::string& key) {
        DES des(key);
        return des.Encrypt(data);
    }
    static EncryptedResult Decrypt(const std::string& data, const std::string& key) {
        DES des(key);
        return des.Decrypt(data);
    }
    static EncryptedResult Encrypt3DES(const std::string& data, const std::string& k1, const std::string& k2, const std::string& k3) {
        TripleDES tdes(k1, k2, k3);
        return tdes.Encrypt(data);
    }
    static EncryptedResult Decrypt3DES(const std::string& data, const std::string& k1, const std::string& k2, const std::string& k3) {
        TripleDES tdes(k1, k2, k3);
        return EncryptedResult(tdes.Decrypt(data));
    }
    template<typename OtherMode> ECB& operator|(const OtherMode&) { return *this; }
};

struct CBC {
    static EncryptedResult Encrypt(const std::string& data, const std::string& key, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        DES des(key);
        auto bits = detail::toBitVector(data);
        des._PKCS7Padding(bits);
        std::vector<bool> prev = iv, out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            std::vector<bool> block(bits.begin() + i, bits.begin() + i + 64);
            for (size_t j = 0; j < 64; ++j)
                block[j] = block[j] ^ prev[j];
            auto enc = des.encrypt(block, false);
            std::copy(enc.begin(), enc.end(), out.begin() + i);
            prev.assign(enc.begin(), enc.end());
        }
        return EncryptedResult(out);
    }
    static EncryptedResult Decrypt(const std::string& data, const std::string& key, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        DES des(key);
        auto bits = detail::toBitVector(data);
        std::vector<bool> prev = iv, out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            std::vector<bool> block(bits.begin() + i, bits.begin() + i + 64);
            auto dec = des.decrypt(block, false);
            for (size_t j = 0; j < 64; ++j)
                out[i + j] = dec[j] ^ prev[j];
            prev.assign(block.begin(), block.end());
        }
        des._PKCS7RemovePadding(out);
        return EncryptedResult(out);
    }
    static EncryptedResult Encrypt3DES(const std::string& data, const std::string& k1, const std::string& k2, const std::string& k3, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        TripleDES tdes(k1, k2, k3);
        auto bits = detail::toBitVector(data);
        tdes.des1_._PKCS7Padding(bits);
        std::vector<bool> prev = iv, out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            std::vector<bool> block(bits.begin() + i, bits.begin() + i + 64);
            for (size_t j = 0; j < 64; ++j)
                block[j] = block[j] ^ prev[j];
            auto enc1 = tdes.des1_.encrypt(block, false);
            auto dec2 = tdes.des2_.decrypt(enc1, false);
            auto enc3 = tdes.des3_.encrypt(dec2, false);
            std::copy(enc3.begin(), enc3.end(), out.begin() + i);
            prev.assign(enc3.begin(), enc3.end());
        }
        return EncryptedResult(out);
    }
    static EncryptedResult Decrypt3DES(const std::string& data, const std::string& k1, const std::string& k2, const std::string& k3, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        TripleDES tdes(k1, k2, k3);
        auto bits = detail::toBitVector(data);
        std::vector<bool> prev = iv, out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            std::vector<bool> block(bits.begin() + i, bits.begin() + i + 64);
            auto dec3 = tdes.des3_.decrypt(block, false);
            auto enc2 = tdes.des2_.encrypt(dec3, false);
            auto dec1 = tdes.des1_.decrypt(enc2, false);
            for (size_t j = 0; j < 64; ++j)
                out[i + j] = dec1[j] ^ prev[j];
            prev.assign(block.begin(), block.end());
        }
        tdes.des1_._PKCS7RemovePadding(out);
        return EncryptedResult(out);
    }
    template<typename OtherMode> CBC& operator|(const OtherMode&) { return *this; }
};

struct CFB {
    static EncryptedResult Encrypt(const std::string& data, const std::string& key, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        DES des(key);
        auto bits = detail::toBitVector(data);
        des._PKCS7Padding(bits);
        std::vector<bool> prev = iv, out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            auto cipher = des.encrypt(prev, false);
            for (size_t j = 0; j < 64; ++j)
                out[i + j] = bits[i + j] ^ cipher[j];
            prev.assign(out.begin() + i, out.begin() + i + 64);
        }
        return EncryptedResult(out);
    }
    static EncryptedResult Decrypt(const std::string& data, const std::string& key, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        DES des(key);
        auto bits = detail::toBitVector(data);
        std::vector<bool> prev = iv, out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            auto cipher = des.encrypt(prev, false);
            for (size_t j = 0; j < 64; ++j)
                out[i + j] = bits[i + j] ^ cipher[j];
            prev.assign(bits.begin() + i, bits.begin() + i + 64);
        }
        des._PKCS7RemovePadding(out);
        return EncryptedResult(out);
    }
    template<typename OtherMode> CFB& operator|(const OtherMode&) { return *this; }
};

struct OFB {
    static EncryptedResult Encrypt(const std::string& data, const std::string& key, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        DES des(key);
        auto bits = detail::toBitVector(data);
        std::vector<bool> prev = iv, out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            prev = des.encrypt(prev, false);
            for (size_t j = 0; j < 64; ++j)
                out[i + j] = bits[i + j] ^ prev[j];
        }
        return EncryptedResult(out);
    }
    static EncryptedResult Decrypt(const std::string& data, const std::string& key, const std::vector<bool>& iv = std::vector<bool>(64, 0)) {
        // OFB decryption is the same as encryption
        return Encrypt(data, key, iv);
    }
    template<typename OtherMode> OFB& operator|(const OtherMode&) { return *this; }
};

struct CTR {
    static EncryptedResult Encrypt(const std::string& data, const std::string& key, uint64_t nonce = 0) {
        DES des(key);
        auto bits = detail::toBitVector(data);
        std::vector<bool> out(bits.size());
        for (size_t i = 0; i < bits.size(); i += 64) {
            uint64_t ctr = nonce + i / 64;
            std::vector<bool> ctr_block(64, 0);
            for (int j = 0; j < 64; ++j)
                ctr_block[63 - j] = (ctr >> j) & 1;
            auto enc = des.encrypt(ctr_block, false);
            for (size_t j = 0; j < 64; ++j)
                out[i + j] = bits[i + j] ^ enc[j];
        }
        return EncryptedResult(out);
    }
    static EncryptedResult Decrypt(const std::string& data, const std::string& key, uint64_t nonce = 0) {
        // CTR decryption is the same as encryption
        return Encrypt(data, key, nonce);
    }
    template<typename OtherMode> CTR& operator|(const OtherMode&) { return *this; }
};

} // namespace DES
