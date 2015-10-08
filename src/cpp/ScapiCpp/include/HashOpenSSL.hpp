#include "Hash.hpp"
/**
* A general adapter class of hash for OpenSSL. <p>
* This class implements all the functionality by passing requests to the adaptee c++ functions,
* like int SHA1_Update(SHA_CTX *c, const void *data, unsigned long len);.
*
* A concrete hash function such as SHA1 represented by the class OpenSSLSHA1 only passes the name of the hash in the constructor
* to this base class.
* Since the underlying library is written in a native language we use the JNI architecture.
*/
class OpenSSLHash : public CryptographicHash {
private:
	int hashSize;
protected:
	long hash; //Pointer to the native hash object.
	virtual ~OpenSSLHash();
public:
	/**
	* Constructs the native hash function using OpenSSL library.
	* @param hashName - the name of the hash. This will be passed to the jni dll function createHash so it will know which hash to create.
	*/
	OpenSSLHash(string hashName);
	int getHashedMsgSize() override { return hashSize;};
	string getAlgorithmName() override;
	void update(byte* in, int inOffset, int inLen) override;
	void hashFinal(byte* out, int outOffset) override;
};

/************************************************************
* Concrete classed of cryptographicHash for different SHA. These classes wraps OpenSSL implementation of SHA*.
*************************************************************/

class OpenSSLSHA1 : public OpenSSLHash , public SHA1 {
public:
	OpenSSLSHA1() : OpenSSLHash("SHA1") {};
};

class OpenSSLSHA224 : public OpenSSLHash, public SHA224 {
public:
	OpenSSLSHA224() : OpenSSLHash("SHA224") {};
};

class OpenSSLSHA256 : public OpenSSLHash, public SHA256{
public:
	OpenSSLSHA256() : OpenSSLHash("SHA256") {};
};

class OpenSSLSHA384 : public OpenSSLHash, public SHA384 {
public:
	OpenSSLSHA384() : OpenSSLHash("SHA384") {};
};

class OpenSSLSHA512 : public OpenSSLHash, public SHA512 {
public:
	OpenSSLSHA512() : OpenSSLHash("SHA512") {};
};

