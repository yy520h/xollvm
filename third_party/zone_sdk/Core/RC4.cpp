#include "RC4.h"
#include <iostream>

void RC4::swap(unsigned char data[], int i, int j)
{
	unsigned char temp = data[i];
	data[i] = data[j];
	data[j] = temp;
}

void RC4::prga(const std::string& plaintext, std::string& cipher)
{
	cipher.resize(plaintext.size());
	for (size_t i = 0; i < plaintext.size(); i++) {
		prgaIndexA = (prgaIndexA + 1) % 256;
		prgaIndexB = (prgaIndexB + sbox[prgaIndexA]) % 256;  // 注意这里用 % 256 而不是 & 256
		swap(sbox, prgaIndexA, prgaIndexB);
		unsigned char k = sbox[(sbox[prgaIndexA] + sbox[prgaIndexB]) % 256];
		cipher[i] = k ^ static_cast<unsigned char>(plaintext[i]);
	}
}

void RC4::encrypt(const std::string& in, std::string& out)
{
	prga(in, out);
}
	
void RC4::setKey(const std::string& key)
{
	prgaIndexA = 0;
	prgaIndexB = 0;
	sizeKey = key.size();
	for (int i = 0; i < 256; i++)
		sbox[i] = static_cast<unsigned char>(i);
	ksa(reinterpret_cast<const unsigned char*>(key.data()));
}

void RC4::ksa(const unsigned char* key)
{
	int j = 0;
	for (int i = 0; i < 256; i++) {
		j = (j + sbox[i] + key[i % sizeKey]) % 256;
		swap(sbox, i, j);
	}
}


RC4::RC4() {
}
