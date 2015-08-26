#include "../include/DlogCryptopp.h"


biginteger cryptoppint_to_biginteger(CryptoPP::Integer cint)
{
	string s = boost::lexical_cast<std::string>(cint);
	s = s.substr(0, s.size() - 1); // from some reason casting cryptoPP to string ends with '.'
	return biginteger(s);
}

CryptoPP::Integer biginteger_to_cryptoppint(biginteger bi)
{
	return CryptoPP::Integer(bi.str().c_str());
}

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

ZpSafePrimeElementCryptoPp::ZpSafePrimeElementCryptoPp(biginteger p, boost::mt19937 prg)
{
	// find a number in the range [1, ..., p-1]
	boost::random::uniform_int_distribution<biginteger> ui(1, p - 1);
	biginteger rand_in_range = ui(prg);
	//calculate its power to get a number in the subgroup and set the power as the element. 
	element = boost::multiprecision::powm(rand_in_range, 2, p);
}

ZpSafePrimeElementCryptoPp::ZpSafePrimeElementCryptoPp(biginteger elementValue)
{
		element = elementValue;
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

CryptoPpDlogZpSafePrime::CryptoPpDlogZpSafePrime(ZpGroupParams * groupParams, boost::mt19937 prg)
{
	boost::mt19937 prime_gen(clock()); // prg for prime checking
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
	pointerToGroup->Initialize(biginteger_to_cryptoppint(p), biginteger_to_cryptoppint(q), biginteger_to_cryptoppint(g));

	//If the generator is not valid, delete the allocated memory and throw exception 
	if (!pointerToGroup->ValidateElement(3, biginteger_to_cryptoppint(g), 0)){
		delete pointerToGroup;
		throw invalid_argument("generator value is not valid");
	}
	//Create the GroupElement - generator with the pointer that return from the native function
	generator = new ZpSafePrimeElementCryptoPp(g, p, false);

	//Now that we have p, we can calculate k which is the maximum length of a string to be converted to a Group Element of this group.
	k = calcK(p);
}

CryptoPpDlogZpSafePrime::CryptoPpDlogZpSafePrime(int numBits, boost::mt19937 prg) {

	this->random_element_gen = prg;

	// create random Zp dlog group and initialise it with the size and generator
	CryptoPP::AutoSeededRandomPool rng; //Random Number Generator
	pointerToGroup = new CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime();
	pointerToGroup->Initialize(rng, numBits);

	// get the generator value
	CryptoPP::Integer gen = pointerToGroup->GetSubgroupGenerator();
	//create the GroupElement - generator with the pointer that returned from the native function
	generator = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(gen));

	biginteger p = cryptoppint_to_biginteger(pointerToGroup->GetModulus());
	biginteger q = cryptoppint_to_biginteger(pointerToGroup->GetSubgroupOrder());
	biginteger xG = ((ZpElement *)generator)->getElementValue();

	groupParams = new ZpGroupParams(q, xG, p);

	//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
	k = calcK(p);
}

int CryptoPpDlogZpSafePrime::calcK(biginteger p) {
	int bitsInp = find_log2_floor(p) + 1;
	//any string of length k has a numeric value that is less than (p-1)/2 - 1
	int k = (bitsInp - 3) / 8;
	//The actual k that we allow is one byte less. This will give us an extra byte to pad the binary string passed to encode to a group element with a 01 byte
	//and at decoding we will remove that extra byte. This way, even if the original string translates to a negative BigInteger the encode and decode functions
	//always work with positive numbers. The encoding will be responsible for padding and the decoding will be responsible for removing the pad.
	k--;
	//For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
	//the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
	if (k > 255) {
		k = 255;
	}
	return k;
}

bool CryptoPpDlogZpSafePrime::isGenerator()
{
	//get the group generator
	CryptoPP::Integer g = pointerToGroup->GetSubgroupGenerator();
	/* call to a crypto++ function that checks the generator validity.
	* 3 is the checking level (full check), g is the generator and 0 is instead of DL_FixedBasedPrecomputation object
	*/
	return pointerToGroup->ValidateElement(3, g, 0);
}

bool CryptoPpDlogZpSafePrime::isMember(GroupElement * element) {

	ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(element);
	// check if element is ZpElementCryptoPp
	if (!zp_element) {
		throw invalid_argument("type doesn't match the group type");
	}

	/* if the element is the identity than it is valid.
	* The function validateElement of crypto++ return false if the element is 1 so we checked it outside.
	*/
	if (zp_element->isIdentity())
		return true;

	/* call to a crypto++ function that checks the element validity.
	* 3 is the checking level (full check), e is the element and 0 is instead of DL_FixedBasedPrecomputation object
	*/
	return pointerToGroup->ValidateElement(3, biginteger_to_cryptoppint(zp_element->getElementValue()), 0);
}

bool CryptoPpDlogZpSafePrime::validateGroup()
{
	CryptoPP::AutoSeededRandomPool rng;
	/* call to crypto++ function validate that checks if the group is valid.
	* it checks the validity of p, q, and the generator.
	* 3 is the checking level - full validate.
	*/
	return pointerToGroup->Validate(rng, 3);
}

GroupElement * CryptoPpDlogZpSafePrime::getInverse(GroupElement * groupElement)
{
	ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement);
	if(! zp_element)
		throw invalid_argument("element type doesn't match the group type");

	CryptoPP::Integer mod = pointerToGroup->GetModulus(); //get the field modulus
	CryptoPP::ModularArithmetic ma(mod); //create ModularArithmetic object with the modulus
    // get the inverse 
	CryptoPP::Integer result = ma.MultiplicativeInverse(biginteger_to_cryptoppint(zp_element->getElementValue()));
	ZpSafePrimeElementCryptoPp * inverseElement = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(result));
	return inverseElement;
}

GroupElement * CryptoPpDlogZpSafePrime::exponentiate(GroupElement * base, biginteger exponent){
	ZpSafePrimeElementCryptoPp * zp_base = dynamic_cast<ZpSafePrimeElementCryptoPp *>(base);
	if (!zp_base)
		throw invalid_argument("element type doesn't match the group type");
	
	//exponentiate the element
	CryptoPP::Integer result = pointerToGroup->ExponentiateElement(biginteger_to_cryptoppint(zp_base->getElementValue()), biginteger_to_cryptoppint(exponent));
	//build a ZpElementCryptoPp element from the result value
	ZpSafePrimeElementCryptoPp * exponentiateElement = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(result));
	return exponentiateElement;
}

GroupElement * CryptoPpDlogZpSafePrime::multiplyGroupElements(GroupElement * groupElement1,	GroupElement * groupElement2){
	ZpSafePrimeElementCryptoPp * zp1 = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement1);
	ZpSafePrimeElementCryptoPp * zp2 = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement2);
	if (!zp1 || !zp2)
		throw invalid_argument("element type doesn't match the group type");
		
	//multiply the element
	CryptoPP::Integer result = pointerToGroup->MultiplyElements(biginteger_to_cryptoppint(zp1->getElementValue()), biginteger_to_cryptoppint(zp2->getElementValue()));
	//build a ZpElementCryptoPp element from the result value
	ZpSafePrimeElementCryptoPp * mulElement = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(result));
	return mulElement;
}

GroupElement * CryptoPpDlogZpSafePrime::simultaneousMultipleExponentiations(vector<GroupElement *> groupElements, vector<biginteger> exponentiations){

	for (int i = 0; i < groupElements.size(); i++) {
		ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElements[i]);
		if (!zp_element) {
			throw invalid_argument("groupElement doesn't match the DlogGroup");
		}
	}

	//currently, in cryptoPpDlogZpSafePrime the native algorithm is faster than the optimized one due to many calls to the JNI.
	//Thus, we operate the native algorithm. In the future we may change this.
	// TODO - THIS IS NOT TRUE ANYMORE. NEED TO FIX THIS.
	return computeNaive(groupElements, exponentiations);
}

GroupElement * CryptoPpDlogZpSafePrime::generateElement(bool bCheckMembership, vector<biginteger> values)
{
	if (values.size() != 1) {
		throw new invalid_argument("To generate an ZpElement you should pass the x value of the point");
	}
	return new ZpSafePrimeElementCryptoPp(values[0], ((ZpGroupParams *)groupParams)->getP(), bCheckMembership);
}

CryptoPpDlogZpSafePrime::~CryptoPpDlogZpSafePrime()
{
	// the dynamic allocation of the Integer.
	delete pointerToGroup;
	// super.finalize(); - no need. happens automatically
}

 GroupElement * CryptoPpDlogZpSafePrime::encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) {
	//Any string of length up to k has numeric value that is less than (p-1)/2 - 1.
	//If longer than k then throw exception.
	if (binaryString.size() > k) {
		throw length_error("The binary array to encode is too long.");
	}

	//Pad the binaryString with a x01 byte in the most significant byte to ensure that the 
	//encoding and decoding always work with positive numbers.
	list<unsigned char> newString(binaryString.begin(), binaryString.end());
	newString.push_front(1);

	//Denote the string of length k by s.
	//Set the group element to be y=(s+1)^2 (this ensures that the result is not 0 and is a square)
	biginteger s(string(newString.begin(), newString.end()));
	biginteger y = boost::multiprecision::powm((s + 1), 2, ((ZpGroupParams *)groupParams)->getP());
	//There is no need to check membership since the "element" was generated so that it is always an element.
	ZpSafePrimeElementCryptoPp * element = new ZpSafePrimeElementCryptoPp(y, ((ZpGroupParams * )groupParams)->getP(), false);
	return element;
}

 const vector<unsigned char> CryptoPpDlogZpSafePrime::decodeGroupElementToByteArray(GroupElement * groupElement) {
	 ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement);
	 if (!(zp_element))
		 throw invalid_argument("element type doesn't match the group type");

	 //Given a group element y, find the two inverses z,-z. Take z to be the value between 1 and (p-1)/2. Return s=z-1
	 biginteger y = zp_element->getElementValue();
	 biginteger p = ((ZpGroupParams * ) groupParams)->getP();
	 boost::multiprecision::sqrt(y) % p;

	 MathAlgorithms::SquareRootResults roots = MathAlgorithms::sqrtModP_3_4(y, p);
	 biginteger goodRoot;
	 biginteger halfP = (p - 1) / 2;
	 if (roots.getRoot1()>1 && roots.getRoot1() < halfP)
		 goodRoot = roots.getRoot1();
	 else
		 goodRoot = roots.getRoot2();
	 goodRoot -= 1;

	 // Remove the padding byte at the most significant position (that was added while encoding)
	 string sgoodRoot = string(goodRoot);
	 sgoodRoot.erase(0, 1);
	 return vector<unsigned char> (sgoodRoot.begin(), sgoodRoot.end());
 }

 const vector<unsigned char> CryptoPpDlogZpSafePrime::mapAnyGroupElementToByteArray(GroupElement * groupElement) {
	 ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement);
	 if (!(zp_element))
		 throw invalid_argument("element type doesn't match the group type");
	 string res = string(zp_element->getElementValue());
	 return vector<unsigned char>(res.begin(), res.end());
 }
