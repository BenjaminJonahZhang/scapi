#include "Dlog.hpp"
// CryptoPP includes
#include <gfpcrypt.h>
#include <cryptlib.h>
#include <osrng.h>


/**
* This class is an adapter class of Crypto++ to a ZpElement in SCAPI.<p>
* It holds a pointer to a Zp element in Crypto++. It implements all the functionality of a Zp element.
*/
class ZpSafePrimeElementCryptoPp : public ZpSafePrimeElement {
private:
	biginteger element;
public:
	/**
	* This constructor accepts x value and DlogGroup.
	* If x is valid, sets it; else, throws exception
	* @param x
	* @param zp
	* @throws IllegalArgumentException
	*/
	ZpSafePrimeElementCryptoPp(biginteger x, biginteger p, bool bCheckMembership);
	/**
	* Constructor that gets DlogGroup and chooses random element with order q.
	* The algorithm is:
	* input: modulus p
	* choose a random element between 1 to p-1
	* calculate element^2 mod p
	*
	* @param p - group modulus
	* @throws IllegalArgumentException
	*/
	ZpSafePrimeElementCryptoPp(biginteger elementOrP, boost::mt19937 prg = boost::mt19937(clock()), bool bUseRandom=false);
	biginteger getElementValue(){
		return element;
	}
	/**
	* This function checks if this element is the identity of the Dlog group.
	* @return <code>true</code> if this element is the identity of the group; <code>false</code> otherwise.
	*/
	bool isIdentity() { return element == 1; }
	/**
	* Checks if the given GroupElement is equal to this groupElement.
	*
	* @param elementToCompare
	* @return true if the given element is equal to this element. false, otherwise.
	*/
	bool ZpSafePrimeElementCryptoPp::operator==(const ZpSafePrimeElementCryptoPp &other) const;
	bool ZpSafePrimeElementCryptoPp::operator!=(const ZpSafePrimeElementCryptoPp &other) const;
	string toString() {
		return "ZpSafePrimeElementCryptoPp [element value=" + string(element) + "]";
	}
	/**
	* @see edu.biu.scapi.primitives.dlog.GroupElement#generateSendableData()
	*/
	GroupElementSendableData * generateSendableData();
};

/**
* This class implements a Dlog group over Zp* utilizing Crypto++'s implementation.<p>
*/
class CryptoPpDlogZpSafePrime :public DlogGroupAbs, public DlogZpSafePrime, public DDH {
private:
	CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * pointerToGroup = NULL; // pointer to the native group object
	/* basic functions for the Dlog functionality */
	long getGenerator(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group);
	char * getP(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group);
	char * getQ(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group);
	long inverseElement(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group, long element);
	long exponentiateElement(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group, long element, char exponent[]);
	long multiplyElements(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group, long element1, long element2);
	void deleteDlogZp(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group);
	bool validateZpGroup(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group);
	bool validateZpGenerator(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group);
	bool validateZpElement(CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime * group, long element);
	int calcK(biginteger p);

public:
	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	* @param groupParams - contains the group parameters
	*/
	CryptoPpDlogZpSafePrime(ZpGroupParams * groupParams, boost::mt19937 prg = boost::mt19937(clock()));

	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	* @param q the order of the group
	* @param g the generator of the group
	* @param p the prime of the group
	*/
	CryptoPpDlogZpSafePrime(string q, string g, string p) : CryptoPpDlogZpSafePrime(new ZpGroupParams(biginteger(q), biginteger(g), biginteger(p))) {};

	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	* @param q the order of the group
	* @param g the generator of the group
	* @param p the prime of the group
	* @throws NoSuchAlgorithmException
	*/
	CryptoPpDlogZpSafePrime(string q, string g, string p, string randNumGenAlg) { throw invalid_argument("not implemented"); };

	/**
	* Initializes the CryptoPP implementation of Dlog over Zp* with random elements
	* @param numBits - number of the prime p bits to generate
	*/
	CryptoPpDlogZpSafePrime(int numBits = 1024, boost::mt19937 prg = boost::mt19937(clock()));

	//creates an int from the given string and calls the appropriate constructor
	CryptoPpDlogZpSafePrime(string numBits) : CryptoPpDlogZpSafePrime(stoi(numBits)) {};

	CryptoPpDlogZpSafePrime(string numBits, string randNumGenAlg) {
		// TODO: NOT IMPLEMENTED 
	}

	/**
	* @return the type of the group - Zp*
	*/
	string getGroupType() { return "Zp*"; }

	/**
	* @return the identity of this Zp group - 1
	*/
	GroupElement * getIdentity() {
		return new ZpSafePrimeElementCryptoPp(1, ((ZpGroupParams *)groupParams)->getP, false);
	}

	/**
	* Creates a random member of this Dlog group
	*
	* @return the random element
	*/
	GroupElement * createRandomElement() {
		//This function overrides the basic implementation of DlogGroupAbs. For the case of Zp Safe Prime this is a more efficient implementation.
		//It calls the package private constructor of ZpSafePrimeElementCryptoPp, which randomly creates an element in Zp.
		return new ZpSafePrimeElementCryptoPp(((ZpGroupParams *)groupParams)->getP(), random);

	}

	/**
	* Checks if the given element is member of this Dlog group
	* @param element
	* @return true if the given element is member of that group. false, otherwise.
	* @throws IllegalArgumentException
	*/
	public boolean isMember(GroupElement element) {

		// check if element is ZpElementCryptoPp
		if (!(element instanceof ZpSafePrimeElementCryptoPp)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}

		return validateZpElement(pointerToGroup, ((ZpSafePrimeElementCryptoPp)element).getPointerToElement());

	}

	/**
	* Checks if the given generator is indeed the generator of the group
	* @return true, is the generator is valid, false otherwise.
	*/
	bool isGenerator() { return validateZpGenerator(pointerToGroup); }

	/**
	* Checks if the parameters of the group are correct.
	* @return true if valid, false otherwise.
	*/
	bool validateGroup() { return validateZpGroup(pointerToGroup); }

	/**
	* Calculates the inverse of the given GroupElement
	* @param groupElement to inverse
	* @return the inverse element of the given GroupElement
	* @throws IllegalArgumentException
	*/
	GroupElement * getInverse(GroupElement * groupElement);

	/**
	* Raises the base GroupElement to the exponent. The result is another GroupElement.
	* @param exponent
	* @param base
	* @return the result of the exponentiation
	* @throws IllegalArgumentException
	*/
	GroupElement * exponentiate(GroupElement * base, biginteger exponent);

	/**
	* Multiplies two GroupElements
	*
	* @param groupElement1
	* @param groupElement2
	* @return the multiplication result
	* @throws IllegalArgumentException
	*/
	GroupElement * multiplyGroupElements(GroupElement * groupElement1, GroupElement * groupElement2);

	/**
	* Computes the product of several exponentiations with distinct bases
	* and distinct exponents.
	* Instead of computing each part separately, an optimization is used to
	* compute it simultaneously.
	* @param groupElements
	* @param exponentiations
	* @return the exponentiation result
	*/
	GroupElement * simultaneousMultipleExponentiations
		(GroupElement[] groupElements, BigInteger[] exponentiations);

	/* (non-Javadoc)
	* @see DlogGroup#generateElement(boolean, java.math.BigInteger[]) @Override
	*/
	GroupElement * generateElement(boolean bCheckMembership, BigInteger... values);

	/**
	* deletes the related Dlog group object
	*/
	protected void finalize() throws Throwable {

		// delete from the dll the dynamic allocation of the Integer.
		deleteDlogZp(pointerToGroup);
		super.finalize();
	}


	/**
	* This function takes any string of length up to k bytes and encodes it to a Group Element.<p>
	* k is calculated upon construction of this group and it depends on the length in bits of p.<p>
	* The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.<p>
	* Therefore, any string of length in bytes up to k can be encoded to a group element but not<p>
	* every group element can be decoded to a binary string in the group of binary strings of length up to 2^k.<p>
	* Thus, the right way to use this functionality is first to encode a byte array and the to decode it, and not the opposite.
	* @throws IndexOutOfBoundsException if the length of the binary array to encode is longer than k
	*/
	GroupElement * encodeByteArrayToGroupElement(char binaryString[]);

	/**
	* This function decodes a group element to a byte array.<p>
	* This function is guaranteed to work properly ONLY if the group element was obtained as a result
	* of encoding a binary string of length in bytes up to k. This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.<p>
	* Therefore, any string of length in bytes up to k can be encoded to a group element but not<p>
	* any group element can be decoded to a binary sting in the group of binary strings of length up to 2^k.
	* @param groupElement the GroupElement to decode
	* @return a byte[] decoding of the group element
	*/
	char * decodeGroupElementToByteArray(GroupElement * groupElement);

	/**
	* This function maps a group element of this dlog group to a byte array.<p>
	* This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array.
	* @return a byte array representation of the given group element
	*/
	char * mapAnyGroupElementToByteArray(GroupElement * groupElement);
};