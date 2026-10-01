
#include "EncryptCore.h"
#include <sstream>
#include <iomanip>



// CRC8 常量初始化
const uint8_t EncryptCore::_crc8Polynomial = 0x07;

// CRC16 常量初始化
const uint16_t EncryptCore::_crc16Polynomial = 0x1021;
const uint16_t EncryptCore::_crc16FinalXor = 0x0000;

// CRC32 常量初始化
const uint32_t EncryptCore::_crc32Polynomial = 0xEDB88320;

// 构造函数，初始化所有CRC表
EncryptCore::EncryptCore() {
	InitializeCrc8Table();
	InitializeCrc16Table();
	InitializeCrc32Table();
}

// 初始化CRC8表
void EncryptCore::InitializeCrc8Table() {
	for (int i = 0; i < 256; i++) {
		uint8_t crc = static_cast<uint8_t>(i);
		for (int j = 0; j < 8; j++) {
			if ((crc & 0x80) != 0) {
				crc = static_cast<uint8_t>((crc << 1) ^ _crc8Polynomial);
			}
			else {
				crc <<= 1;
			}
		}
		_crc8Table[i] = crc;
	}
}

// 初始化CRC16表
void EncryptCore::InitializeCrc16Table() {
	for (uint16_t i = 0; i < 256; i++) {
		uint16_t crc = i;
		crc <<= 8; // 左移8位，不进行位反转

		for (int j = 0; j < 8; j++) {
			if ((crc & 0x8000) != 0) { // 检查最高位
				crc = static_cast<uint16_t>((crc << 1) ^ _crc16Polynomial);
			}
			else {
				crc <<= 1;
			}
		}
		_crc16Table[i] = crc;
	}
}

// 初始化CRC32表
void EncryptCore::InitializeCrc32Table() {
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t crc = i;
		for (int j = 0; j < 8; j++) {
			if ((crc & 0x00000001) != 0) {
				crc = static_cast<uint32_t>((crc >> 1) ^ _crc32Polynomial);
			}
			else {
				crc >>= 1;
			}
		}
		_crc32Table[i] = crc;
	}
}

// 将字符串转换为UTF8字节（输入按 UTF-8 解释，与原先 codecvt 路径对合法 UTF-8 等价）
std::vector<uint8_t> EncryptCore::StringToUtf8Bytes(const std::string& input) {
	return std::vector<uint8_t>(input.begin(), input.end());
}

// 计算CRC8
std::string EncryptCore::CalculateCRC8(const std::string& input) {
	if (input.empty()) {
		return "00";
	}

	std::vector<uint8_t> bytes = StringToUtf8Bytes(input);
	uint8_t crc = 0;

	for (uint8_t b : bytes) {
		crc = _crc8Table[crc ^ b];
	}

	std::stringstream ss;
	ss << std::uppercase << std::setw(2) << std::setfill('0') << std::hex
		<< static_cast<int>(crc);
	return ss.str();
}

// 计算CRC16_CCITTFALSE
std::string EncryptCore::CalculateCRC16(const std::string& input) {
	if (input.empty()) {
		return "0000";
	}

	std::vector<uint8_t> bytes = StringToUtf8Bytes(input);
	uint16_t crc = 0xFFFF; // 初始值

	for (uint8_t b : bytes) {
		crc = static_cast<uint16_t>((crc << 8) ^ _crc16Table[((crc >> 8) ^ b) & 0xFF]);
	}

	crc ^= _crc16FinalXor;

	std::stringstream ss;
	ss << std::uppercase << std::setw(4) << std::setfill('0') << std::hex << crc;
	return ss.str();
}

// 计算CRC32
std::string EncryptCore::CalculateCRC32(const std::string& input) {
	if (input.empty()) {
		return "00000000";
	}

	std::vector<uint8_t> bytes = StringToUtf8Bytes(input);
	uint32_t crc = 0xFFFFFFFF;

	for (uint8_t b : bytes) {
		crc = (crc >> 8) ^ _crc32Table[(crc & 0xFF) ^ b];
	}

	crc ^= 0xFFFFFFFF;

	std::stringstream ss;
	ss << std::uppercase << std::setw(8) << std::setfill('0') << std::hex << crc;
	return ss.str();
}


std::string EncryptCore::StringToHex(const std::string& input) {
	Cryption m_cryption;
	return m_cryption.stringToHex(input);
}

std::string EncryptCore::HexToString(const std::string& hexString) {
	Cryption m_cryption;
	return m_cryption.hexToString(hexString);
}

std::string EncryptCore::CalculateMD5Hash(const std::string& input) {
	return MD5(input).toStr();
}


std::string EncryptCore::ToEncrypt(const std::string& plainText, const std::string& key, const std::string& iv, eum_EncryptType arg_encryptType) {
	try
	{

		Cryption m_cryption;
		//std::cout << "t" << m_cryption.AESEncrypt("123", "12312312313", "6666666666666");

		switch (arg_encryptType)
		{
		case /*ns_ZoneHelper::*/eum_EncryptType::AES:
		{
			return m_cryption.AESEncrypt(plainText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::RC4:
		{
			return m_cryption.RC4_Encrypt(plainText, key);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::DES3:
		{
			return m_cryption.DES3_Encrypt(plainText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::ChaCha20_en:
		{
			return m_cryption.ChaCha20_Encrypt(plainText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::RSA:
		{
			return m_cryption.RSAEncrypt(plainText, key);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::NTRU:
		{
			return m_cryption.AESEncrypt(plainText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::ECC:
		{
			return m_cryption.ECC_Encrypt(plainText, key);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::None:
			break;
		case /*ns_ZoneHelper::*/eum_EncryptType::Plaintext:
		{
			return plainText;
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Base32:
		{
			return m_cryption.Base32Encode(plainText);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Base64:
		{
			return base64_encode(plainText);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Hex:
		{
			return m_cryption.HexEncode(plainText);
			break;
		}
		default:
			break;
		}
	}
	catch (const std::exception& ex)
	{
		return ex.what();
	}
	return "";
}

std::string EncryptCore::ToDecrypt(const std::string& cipherText, const std::string& key, const std::string& iv, eum_EncryptType arg_encryptType) {
	try
	{

		Cryption m_cryption;
		switch (arg_encryptType)
		{
		case /*ns_ZoneHelper::*/eum_EncryptType::AES:
		{
			return m_cryption.AESDecrypt(cipherText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::RC4:
		{
			return m_cryption.RC4_Decrypt(cipherText, key);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::DES3:
		{
			return m_cryption.DES3_Decrypt(cipherText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::ChaCha20_en:
		{
			return m_cryption.ChaCha20_Decrypt(cipherText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::RSA:
		{
			return m_cryption.RSADecrypt(cipherText, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::NTRU:
		{
			return m_cryption.AESDecrypt(cipherText, key, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::ECC:
		{
			return m_cryption.ECC_Decrypt(cipherText, iv);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::None:
			break;
		case /*ns_ZoneHelper::*/eum_EncryptType::Plaintext:
		{
			return cipherText;
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Base32:
		{
			return m_cryption.Base32Decode(cipherText);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Base64:
		{
			return base64_decode(cipherText);
			break;
		}
		case /*ns_ZoneHelper::*/eum_EncryptType::Hex:
		{
			return m_cryption.HexDecode(cipherText);
			break;
		}
		default:
			break;
		}
	}
	catch (const std::exception& ex)
	{
		return ex.what();
	}
	return "";
}