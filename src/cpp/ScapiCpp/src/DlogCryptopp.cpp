#include "../include/DlogCryptopp.h"

/*************************************************/
/*ZpSafePrimeElementCryptoPp*/
/*************************************************/
ZpSafePrimeElementCryptoPp::ZpSafePrimeElementCryptoPp(biginteger x, biginteger p, bool bCheckMembership){
	if (bCheckMembership) {
		biginteger q = (p - 1) / 2; 
		//if the element is in the expected range, set it. else, throw exception
		if (x > 0 && x <= (p - 1))
		{
			if (boost::multiprecision::powm(x, q, p) == 1) // x^q mod p == 1
				element = x;
			else
				throw invalid_argument("Cannot create Zp element. Requested value " + (string)x + " is not in the range of this group.");
		}
		else
			throw invalid_argument("Cannot create Zp element. Requested value " + (string)x + " is not in the range of this group.");
	}
	else
		element = x;
}

ZpSafePrimeElementCryptoPp::ZpSafePrimeElementCryptoPp(biginteger elementOrP, boost::mt19937 prg = boost::mt19937(clock()), bool bUseRandom = false)
{
	if (bUseRandom)
	{
		// find a number in the range [1, ..., p-1]
		boost::random::uniform_int_distribution<biginteger> ui(1, elementOrP - 1);
		biginteger rand_in_range = ui(prg);

		//calculate its power to get a number in the subgroup and set the power as the element. 
		element = boost::multiprecision::powm(rand_in_range, 2, elementOrP);
	}
	else
		element = elementOrP;
}

bool ZpSafePrimeElementCryptoPp::operator==(const ZpSafePrimeElementCryptoPp &other) const {
	return this->element == other.element;
}

bool ZpSafePrimeElementCryptoPp::operator!=(const ZpSafePrimeElementCryptoPp &other) const {
	return !(*this == other);
}

GroupElementSendableData * ZpSafePrimeElementCryptoPp::generateSendableData() {
	return new ZpElementSendableData(getElementValue());
}
/*************************************************/


/*************************************************/
/**** CryptoPpDlogZpSafePrime ***/
/*************************************************/

CryptoPpDlogZpSafePrime::CryptoPpDlogZpSafePrime(ZpGroupParams * groupParams, boost::mt19937 prg = boost::mt19937(clock()))
{
	this->random_element_gen = prg;
	biginteger p = groupParams->getP();
	biginteger q = groupParams->getQ();
	biginteger g = groupParams->getXg();

	// if p is not 2q+1 throw exception
	if (!(q * 2 + 1 == p)) {
		throw invalid_argument("p must be equal to 2q+1");
	}
	// if p is not a prime throw exception

	if (!miller_rabin_test(p, 40, prime_gen)) {
		throw invalid_argument("p must be a prime");
	}
	// if q is not a prime throw exception
	if (!miller_rabin_test(q, 40, prime_gen)) {
		throw invalid_argument("q must be a prime");
	}
	// set the inner parameters
	this->groupParams = groupParams;

	//Create CryptoPP Dlog group with p, ,q , g.
	//The validity of g will be checked after the creation of the group because the check need the pointer to the group
	pointerToGroup = new CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime();
	pointerToGroup->Initialize(CryptoPP::Integer(p), CryptoPP::Integer(q), CryptoPP::Integer(g));

	//If the generator is not valid, delete the allocated memory and throw exception 
	if (!validateZpGenerator(pointerToGroup)) {
		deleteDlogZp(pointerToGroup);
		throw invalid_argument("generator value is not valid");
	}
	//Create the GroupElement - generator with the pointer that return from the native function
	generator = new ZpSafePrimeElementCryptoPp(g, p, false);

	//Now that we have p, we can calculate k which is the maximum length of a string to be converted to a Group Element of this group.
	k = calcK(p);
}

CryptoPpDlogZpSafePrime::CryptoPpDlogZpSafePrime(int numBits, boost::mt19937 prg = boost::mt19937(clock())) {

	this->random_element_gen = prg;

	// create random Zp dlog group and initialise it with the size and generator
	CryptoPP::AutoSeededRandomPool rng; //Random Number Generator
	pointerToGroup = new CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime();
	pointerToGroup->Initialize(rng, numBits);

	// get the generator value
	CryptoPP::Integer gen = pointerToGroup->GetSubgroupGenerator();
	//create the GroupElement - generator with the pointer that returned from the native function
	generator = new ZpSafePrimeElementCryptoPp(gen.);

	BigInteger p = new BigInteger(getP(pointerToGroup));
	BigInteger q = new BigInteger(getQ(pointerToGroup));
	BigInteger xG = ((ZpElement)generator).getElementValue();

	groupParams = new ZpGroupParams(q, xG, p);

	//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
	k = calcK(p);
}