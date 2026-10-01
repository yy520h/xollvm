#ifndef ARC4_H_
#define ARC4_H_

#include <string>
class RC4 {
public:

	void setKey(const std::string& key);
	void encrypt(const std::string& in, std::string& out);
	RC4();
protected:
	void ksa(const unsigned char* key);
	void swap(unsigned char data[], int i, int j);
	void prga(const std::string& plaintext, std::string& cipher);
	unsigned char sbox[256];
	int sizeKey, prgaIndexA, prgaIndexB;
};



#endif