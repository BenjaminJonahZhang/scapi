#pragma once

#include "Dlog.hpp"
#include <random>
// CryptoPP includes
#ifdef __linux__ 
#include <crypto++/gfpcrypt.h>
#include <crypto++/cryptlib.h>
#include <crypto++/osrng.h>
#elif _WIN32
#include <gfpcrypt.h>
#include <cryptlib.h>
#include <osrng.h>
#endif

/**********************/
/**** Helpers *********/
/**********************/
biginteger cryptoppint_to_biginteger(CryptoPP::Integer cint);
CryptoPP::Integer biginteger_to_cryptoppint(biginteger bi);

/**
* This class is an adapter class of Crypto++ to a ZpElement in SCAPI.<p>
* It holds a pointer to a Zp element in Crypto++. It implements all the functionality of a Zp element.
*/
class ZpSafePrimeElementCryptoPp : public ZpSafePrimeElement {
public:
	ZpSafePrimeElementCryptoPp(biginteger x, biginteger p, 
		bool bCheckMembership) : ZpSafePrimeElement(x, p, bCheckMembership) {};
	ZpSafePrimeElementCryptoPp(biginteger p, mt19937 prg) : ZpSafePrimeElement(p, prg) {};
	ZpSafePrimeElementCryptoPp(biginteger elementValue) : ZpSafePrimeElement(elementValue) {};
	virtual string toString() {
		return "ZpSafePrimeElementCryptoPp [element value=" + string(element) + "]";
	};
};

/**
* This class implements a Dlog group over Zp* utilizing Crypto++'s implementation.<p>
*/
class CryptoPpDlogZpSafePrime :public DlogGroupAbs, public DDH {//public DlogZpSafePrime, 
private:
	CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * pointerToGroup = NULL; // pointer to the native group object
	int calcK(biginteger p);

protected:
	/**
	* deletes the related Dlog group object
	*/
	virtual ~CryptoPpDlogZpSafePrime();

public:
	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	* @param groupParams - contains the group parameters
	*/
	CryptoPpDlogZpSafePrime(ZpGroupParams * groupParams, mt19937 prg = mt19937(clock()));

	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	* @param q the order of the group
	* @param g the generator of the group
	* @param p the prime of the group
	*/
	CryptoPpDlogZpSafePrime(string q, string g, string p) : 
		CryptoPpDlogZpSafePrime(new ZpGroupParams(biginteger(q), biginteger(g), biginteger(p))) {};

	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	* @param q the order of the group
	* @param g the generator of the group
	* @param p the prime of the group
	*/
	CryptoPpDlogZpSafePrime(string q, string g, string p, string randNumGenAlg) { 
		throw NotImplementedException(
			"CryptoPpDlogZpSafePrime((string q, string g, string p, string randNumGenAlg) is not implemented"
	); };

	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with random elements
	* @param numBits - number of the prime p bits to generate
	*/
	CryptoPpDlogZpSafePrime(int numBits = 1024, mt19937 prg = mt19937(clock()));

	//creates an int from the given string and calls the appropriate constructor
	CryptoPpDlogZpSafePrime(string numBits) : CryptoPpDlogZpSafePrime(stoi(numBits)) {};

	CryptoPpDlogZpSafePrime(string numBits, string randNumGenAlg) {
		throw NotImplementedException(
			"CryptoPpDlogZpSafePrime(string numBits, string randNumGenAlg) is not implemented");
	}

	string getGroupType() { return "Zp*"; }
	GroupElement * getIdentity() {
		return new ZpSafePrimeElementCryptoPp(1, ((ZpGroupParams *)groupParams)->getP(), false);
	}
	GroupElement * createRandomElement() override {
		// this function overrides the basic implementation of DlogGroupAbs. For the case of Zp Safe Prime this is a more efficient implementation.
		// it calls the package private constructor of ZpSafePrimeElementCryptoPp, which randomly creates an element in Zp.
		return new ZpSafePrimeElementCryptoPp(((ZpGroupParams *)groupParams)->getP(), random_element_gen);
	}

	bool isMember(GroupElement * element) override; 
	bool isGenerator() override;
	bool validateGroup() override;
	GroupElement * getInverse(GroupElement * groupElement) override;
	GroupElement * exponentiate(GroupElement * base, biginteger exponent) override;
	GroupElement * multiplyGroupElements(GroupElement * groupElement1, GroupElement * groupElement2) override;
	GroupElement * simultaneousMultipleExponentiations(vector<GroupElement *> groupElements, vector<biginteger> exponentiations) override; 
	GroupElement * generateElement(bool bCheckMembership, vector<biginteger> values) override;
	GroupElement * encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;
	const vector<byte> decodeGroupElementToByteArray(GroupElement * groupElement) override;
	virtual const vector<byte>  mapAnyGroupElementToByteArray(GroupElement * groupElement) override;
	virtual GroupElement * reconstructElement(bool bCheckMembership, GroupElementSendableData * data) override;
};
