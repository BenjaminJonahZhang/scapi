#ifndef SCAPI_DLOG_OPENSSL_H
#define SCAPI_DLOG_OPENSSL_H

#include <openssl/dh.h>
#include <openssl/rand.h>
#include "Dlog.hpp"

/**********************/
/**** Helpers *********/
/**********************/
biginteger opensslbignum_to_biginteger(BIGNUM * bint);
BIGNUM * biginteger_to_opensslbignum(biginteger bi);

class OpenSSLDlogZpAdapter {
private:
	DH* dlog;
	BN_CTX* ctx;
public:
	OpenSSLDlogZpAdapter(DH* dlog, BN_CTX* ctx);
	~OpenSSLDlogZpAdapter();
	DH* getDlog() { return dlog; };
	BN_CTX* getCTX() { return ctx; };
	bool validateElement(BIGNUM* element);
};

/**
* This class is an adapter to ZpElement in OpenSSL library.<p>
* It holds a pointer to an OpenSSL's Zp element and implements all the functionality of a Zp element.
*/
class OpenSSLZpSafePrimeElement : public ZpSafePrimeElement {
protected:
	~OpenSSLZpSafePrimeElement() {};
public:
	OpenSSLZpSafePrimeElement(biginteger x, biginteger p, bool bCheckMembership) : ZpSafePrimeElement(x, p, bCheckMembership) {};
	OpenSSLZpSafePrimeElement(biginteger p, mt19937 prg) : ZpSafePrimeElement(p, prg) {};
	OpenSSLZpSafePrimeElement(biginteger elementValue) : ZpSafePrimeElement(elementValue) {};
	virtual string toString() {
		return "OpenSSLZpSafePrimeElement  [element value=" + string(element) + "]";
	};
};

/**
* This class implements a Dlog group over Zp* utilizing OpenSSL's implementation.<p>
*/
class OpenSSLDlogZpSafePrime : public DlogGroupAbs, public DDH {
private:
	OpenSSLDlogZpAdapter* dlog; // Pointer to the native group object.
	OpenSSLDlogZpAdapter* createOpenSSLDlogZpAdapter(biginteger p, biginteger q, biginteger g);
	OpenSSLDlogZpAdapter * createRandomOpenSSLDlogZpAdapter(int numBits);
	int calcK(biginteger p);

protected:
	virtual ~OpenSSLDlogZpSafePrime();

public:
	/**
	* Initializes the OpenSSL implementation of Dlog over Zp* with the given groupParams.
	*/
	OpenSSLDlogZpSafePrime(ZpGroupParams * groupParams, mt19937 prg = mt19937(clock()));
	OpenSSLDlogZpSafePrime(string q, string g, string p) : OpenSSLDlogZpSafePrime(
		new ZpGroupParams(biginteger(q), biginteger(g), biginteger(p))) {};
	/**
	* Default constructor. Initializes this object with 1024 bit size.
	*/
	OpenSSLDlogZpSafePrime(int numBits = 1024, mt19937 prg = mt19937(clock()));
	OpenSSLDlogZpSafePrime(string numBits) : OpenSSLDlogZpSafePrime(stoi(numBits)) {};
	OpenSSLDlogZpSafePrime(int numBits, string randNumGenAlg) { /* TODO: implement */ };

	string getGroupType() override { return "Zp*"; }
	GroupElement * getIdentity() override;
	GroupElement * createRandomElement() override;
	bool isMember(GroupElement * element) override;
	bool isGenerator() override;
	bool validateGroup() override;
	GroupElement * getInverse(GroupElement * groupElement) override;
	GroupElement * exponentiate(GroupElement * base, biginteger exponent) override;
	GroupElement * exponentiateWithPreComputedValues(GroupElement * groupElement, biginteger exponent) override { return exponentiate(groupElement, exponent); };
	GroupElement * multiplyGroupElements(GroupElement * groupElement1, GroupElement * groupElement2) override;
	GroupElement * simultaneousMultipleExponentiations(vector<GroupElement *> groupElements, vector<biginteger> exponentiations) override;
	GroupElement *generateElement(bool bCheckMembership, vector<biginteger> values) override;
	GroupElement * reconstructElement(bool bCheckMembership, GroupElementSendableData * data) override;
	const vector<byte> decodeGroupElementToByteArray(GroupElement * groupElement) override;
	GroupElement * encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;
	virtual const vector<byte>  mapAnyGroupElementToByteArray(GroupElement * groupElement) override;
};

#endif