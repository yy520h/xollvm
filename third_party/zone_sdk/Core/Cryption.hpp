#pragma once
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <string>
#include <vector>
#include <memory>
#include <random>
#include <algorithm>
#include <numeric>

#include "base64.h"
#include <regex>

#include "aes.hpp"
#include "RC4.h"
#include "des.hpp"

class Cryption
{
public:

	// 将普通字符串转换为十六进制字符串
	static	std::string stringToHex(const std::string& input) {
		std::ostringstream hexStream;
		hexStream << std::hex << std::setfill('0');
		for (unsigned char c : input) {
			//hexStream << std::setw(2) << static_cast<unsigned>(c);
			hexStream << std::hex << std::setw(2) << static_cast<unsigned>(c);

		}
		return hexStream.str();
	}

	// 将十六进制字符串转换为普通字符串
	static	std::string hexToString(const std::string& hexString) {
		std::string result;
		for (size_t i = 0; i < hexString.length(); i += 2) {
			std::istringstream converter(hexString.substr(i, 2));
			unsigned value;
			converter >> std::hex >> value;
			result.push_back(static_cast<char>(value));
		}
		return result;
	}

	// 判断字符串是否是 Base64 编码
	static	bool isBase64(const std::string& str) {
		// 检查长度是否为4的倍数
		if (str.length() % 4 != 0) {
			return false;
		}

		// 定义 Base64 合法字符的正则表达式
		static const std::regex base64Regex("^[A-Za-z0-9+/]*={0,2}$");

		// 检查字符串是否匹配 Base64 格式
		if (!std::regex_match(str, base64Regex)) {
			return false;
		}

		return true;
	}

	// 判断字符串是正常字符串还是 Base64 编码,true=是base64编码,false=不是base64
	static	bool checkStringType(const std::string& str) {
		if (isBase64(str)) {
			try {
				// 尝试解码
				base64_decode(str);
				//return "Base64编码字符串";
				return true;
			}
			catch (const std::invalid_argument&) {
				//return "无效的Base64字符串";
				return false;
			}
		}
		//return "正常字符串";
		return false;

	}


	std::string AESEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {


		//std::string key = AES::SecureByteGenerator::GenKeyBlock(AES::AES128KS).toString();
		//std::string iv = AES::SecureByteGenerator::GenIvBlock().toString();

		// CBC Parallel
		auto cbc_par = AES::CBC::ParallelEncryption(plaintext, key, iv);

		//std::cout << "\nCBC Parallel ciphertext (hex): " << cbc_par.toHex() << std::endl;


		try
		{


		}
		catch (const std::exception& e)
		{
			//std::cout << "Cryption.hpp->base64_encode->: " << e.what() << std::endl;
		}
		catch (...)
		{
			//std::cout << "Cryption.hpp->base64_encode->: ...E" << std::endl;
		}
		return cbc_par.toBase64();
	}

	std::string AESDecrypt(const std::string& ciphertextBase64, const std::string& key, const std::string& iv) {

		try
		{
			std::string ciphertext = base64_decode(ciphertextBase64);
			//std::string plaintext(ciphertext.length(), '\0');
			std::vector<uint8_t> ciphertext_x(ciphertext.begin(), ciphertext.end());
			auto decrypted_cbc_par = AES::CBC::ParallelDecryption(ciphertext_x, key, iv);

			return decrypted_cbc_par.toString();
		}
		catch (const std::exception& e)
		{
			//std::cout << "Cryption.hpp->base64_encode->: " << e.what() << std::endl;
		}
		catch (...)
		{
			//std::cout << "Cryption.hpp->base64_encode->: ...E" << std::endl;
		}
		return "";
	}


#pragma region RSA


	/// <summary>
	/// ENCRYPTION_OAEP SHA-256
	/// </summary>
	/// <param name="plaintext"></param>
	/// <param name="publicKey">用this->softUser.soft_key_user</param>
	/// <returns></returns>
	std::string RSAEncrypt(const std::string& plaintext, const std::string& publicKey) {

		//https://stackoverflow.com/questions/75635456/node-crypto-error-error0409a06ersa-routinesrsa-padding-add-pkcs1-oaep-mgf1d
		//RSA 无法加密过长的字符串,例如我的 公告,就无法加密
		return "";
	}

	/// <summary>
	/// ENCRYPTION_OAEP SHA-256
	/// </summary>
	/// <param name="ciphertext"></param>
	/// <param name="privateKey">用this->softUser.soft_iv_user</param>
	/// <returns></returns>
	std::string RSADecrypt(const std::string& ciphertext, const std::string& privateKey) {

		return "";
	}


#pragma endregion


#pragma region 3DES

	//std::vector<bool> stringToBits(const std::string& str) {
	//	std::vector<bool> bits;
	//	for (unsigned char ch : str) {
	//		for (int i = 7; i >= 0; --i) {
	//			bits.push_back((ch >> i) & 1);
	//		}
	//	}
	//	return bits;
	//}

   // 字符串转位向量
	std::vector<bool> stringToBits(const std::string& str) {
		std::vector<bool> bits;
		for (unsigned char ch : str) {
			for (int i = 7; i >= 0; --i) {
				bits.push_back((ch >> i) & 1);
			}
		}
		return bits;
	}

	// 安全的密钥分割函数
	void splitKey(const std::string& key, std::string& key1, std::string& key2, std::string& key3) {
		// 确保密钥长度至少为24字节
		std::string paddedKey = key;
		if (paddedKey.length() < 24) {
			// 如果密钥不足24字节，用零填充或重复密钥
			paddedKey.resize(24, '\0');
		}

		key1 = paddedKey.substr(0, 8);
		key2 = paddedKey.substr(8, 8);
		key3 = paddedKey.substr(16, 8);

		// 验证每个子密钥长度
		if (key1.length() != 8 || key2.length() != 8 || key3.length() != 8) {
			throw std::invalid_argument("Failed to create valid 8-byte keys");
		}
	}

	// 3DES 加密
	std::string DES3_Encrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {


		// 验证IV长度
		if (iv.size() != 8) {
			throw std::invalid_argument("IV must be exactly 8 bytes");
		}

		// 验证密钥长度
		if (key.empty()) {
			throw std::invalid_argument("Key cannot be empty");
		}

		std::vector<bool> ivBits = stringToBits(iv);

		std::string key1, key2, key3;
		splitKey(key, key1, key2, key3);
		//auto tdes_cbc_enc = DES::CBC::Encrypt(plaintext, key, ivBits);
		auto tdes_cbc_enc = DES::CBC::Encrypt3DES(plaintext, key1, key2, key3, ivBits);
		//std::cout << "3DES CBC Encrypted (hex): " << tdes_cbc_enc.toHex() << std::endl;

		return tdes_cbc_enc.toBase64();
	}

	// 3DES 解密
	std::string DES3_Decrypt(const std::string& ciphertextBase64, const std::string& key, const std::string& iv) {

		std::string ciphertext = base64_decode(ciphertextBase64);
		// 验证IV长度
		if (iv.size() != 8) {
			throw std::invalid_argument("IV must be exactly 8 bytes");
		}

		// 验证密钥长度
		if (key.empty()) {
			throw std::invalid_argument("Key cannot be empty");
		}

		std::vector<bool> ivBits = stringToBits(iv);

		std::string key1, key2, key3;
		splitKey(key, key1, key2, key3);
		//auto tdes_cbc_dec = DES::CBC::Decrypt(ciphertext, key, ivBits);
		auto tdes_cbc_dec = DES::CBC::Decrypt3DES(ciphertext, key1, key2, key3, ivBits);

		return tdes_cbc_dec.toString();
	}



#pragma endregion


#pragma region RC4



	// RC4 加密
	std::string RC4_Encrypt(const std::string& plaintext, const std::string& key) {
		std::string out_text_en = "";
		RC4 rc4;
		rc4.setKey(key);
		rc4.encrypt(plaintext, out_text_en);

		return base64_encode(out_text_en);
	}

	// RC4 解密
	std::string RC4_Decrypt(const std::string& ciphertextBase64, const std::string& key) {
		std::string out_text_de = "";
		RC4 rc4_de;
		rc4_de.setKey(key);
		rc4_de.encrypt(base64_decode(ciphertextBase64), out_text_de);

		return out_text_de;
	}


#pragma endregion


#pragma region ChaCha20 

	std::string ChaCha20_Encrypt(const std::string& plaintext, const std::string& key, const std::string& nonce) {

		return "";
	}

	std::string ChaCha20_Decrypt(const std::string& ciphertextBase64, const std::string& key, const std::string& nonce) {

		return "";
	}

#pragma endregion


#pragma region ECC


	// 使用ECC公钥加密
	std::string ECC_Encrypt(const std::string& plaintext, const std::string& publicKeyPEM) {

		return "";
	}

	// 使用ECC私钥解密
	std::string ECC_Decrypt(const std::string& ciphertext, const std::string& privateKeyPEM) {

		return "";
	}
#pragma endregion



#pragma region SHA[256,512]

	// Convert a byte array to a hex string
	std::string to_hex(const std::vector<unsigned char>& bytes) {
		std::ostringstream oss;
		for (auto byte : bytes) {
			oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
		}
		return oss.str();
	}

#pragma endregion




#pragma region Base32

	// Base32 字母表（RFC 4648）
	const char* base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	// 查找字符在字母表中的索引
	int findIndex(char c) {
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= '2' && c <= '7') return 26 + (c - '2');
		return -1; // 无效字符
	}

	std::string Base32Encode(const std::string& input) {
		if (input.empty()) return "";

		std::string encoded;
		uint32_t buffer = 0; // 用于存储待处理的位
		int bits_available = 0; // 缓冲区中可用的位数
		const uint8_t* data = reinterpret_cast<const uint8_t*>(input.data());
		size_t length = input.size();

		for (size_t i = 0; i < length; ++i) {
			// 将当前字节加入缓冲区（左移现有位数）
			buffer = (buffer << 8) | data[i];
			bits_available += 8;

			// 当缓冲区中有至少5位时，提取5位进行编码
			while (bits_available >= 5) {
				// 提取最高的5位
				int five_bits = (buffer >> (bits_available - 5)) & 0x1F;
				encoded += base32Alphabet[five_bits];
				bits_available -= 5;
			}
		}

		// 处理剩余的位（1-4位）
		if (bits_available > 0) {
			// 左移补0，使其达到5位
			int five_bits = (buffer << (5 - bits_available)) & 0x1F;
			encoded += base32Alphabet[five_bits];
		}

		// 计算需要的填充数
		size_t padding = (8 - (encoded.size() % 8)) % 8;
		encoded.append(padding, '=');

		return encoded;
	}

	std::string Decode(const std::string& input) {
		std::vector<uint8_t> decoded;
		uint32_t buffer = 0; // 用于存储待处理的位
		int bits_available = 0; // 缓冲区中可用的位数

		for (char c : input) {
			// 跳过填充符
			if (c == '=') break;

			// 查找字符在字母表中的索引
			int val = findIndex(c);
			if (val == -1) continue; // 跳过无效字符

			// 将5位加入缓冲区
			buffer = (buffer << 5) | val;
			bits_available += 5;

			// 当缓冲区中有至少8位时，提取一个字节
			if (bits_available >= 8) {
				uint8_t byte = (buffer >> (bits_available - 8)) & 0xFF;
				decoded.push_back(byte);
				bits_available -= 8;
			}
		}

		return std::string(decoded.begin(), decoded.end());
	}

	// 解码函数
	std::string Base32Decode(const std::string& encoded) {
		std::vector<uint8_t> decoded;
		int buffer = 0, bitsLeft = 0;

		for (char c : encoded) {
			if (c == '=' || !std::isalnum(c)) continue;

			c = std::toupper(c);
			int val;
			if (c >= 'A' && c <= 'Z') val = c - 'A';
			else if (c >= '2' && c <= '7') val = 26 + (c - '2');
			else continue;

			buffer <<= 5;
			buffer |= val;
			bitsLeft += 5;

			if (bitsLeft >= 8) {
				decoded.push_back((buffer >> (bitsLeft - 8)) & 0xFF);
				bitsLeft -= 8;
			}
		}

		return std::string(decoded.begin(), decoded.end());
	}

#pragma endregion


#pragma region Hex


	std::string HexEncode(const std::string& text) {
		if (text.empty()) {
			return "";
		}

		const std::string hexChars = "0123456789ABCDEF";
		std::stringstream sb;

		for (unsigned char b : text) {
			sb << hexChars[(b >> 4) & 0x0F] << hexChars[b & 0x0F];
		}

		return sb.str();
	}

	std::string HexDecode(const std::string& hexString) {
		if (hexString.empty()) {
			return "";
		}

		// 移除所有空格
		std::string input;
		for (char c : hexString) {
			if (!isspace(c)) {
				input += c;
			}
		}

		// 检查长度是否为偶数
		if (input.length() % 2 != 0) {
			//throw std::invalid_argument("长度必须是偶数");
			throw std::invalid_argument("The length must be even");
		}

		std::stringstream sb;
		for (size_t i = 0; i < input.length(); i += 2) {
			std::string byteString = input.substr(i, 2);
			try {
				unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
				sb << byte;
			}
			catch (const std::exception&) {
				throw std::invalid_argument("无效的 Hex 字符串格式: " + byteString);
			}
		}

		return sb.str();
	}

#pragma endregion
};

