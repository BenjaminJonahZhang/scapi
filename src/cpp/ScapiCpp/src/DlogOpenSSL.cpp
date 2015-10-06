#include "../include/DlogOpenSSL.hpp"

biginteger opensslbignum_to_biginteger(BIGNUM * bint)
{
	char * s = BN_bn2dec(bint);
	return biginteger(s);
}

BIGNUM * biginteger_to_opensslbignum(biginteger bi)
{
	BIGNUM *bn = NULL;
	BN_dec2bn(&bn, bi.str().c_str());
	return bn;
}

/*************************************************/
/**** OpenSSLDlogZpAdapter ***/
/*************************************************/

OpenSSLDlogZpAdapter::OpenSSLDlogZpAdapter(DH* dh, BN_CTX* ctx) {
	this->dlog = dh;
	this->ctx = ctx;
}

OpenSSLDlogZpAdapter::~OpenSSLDlogZpAdapter() {
	BN_CTX_free(ctx);
	DH_free(dlog);
}

bool OpenSSLDlogZpAdapter::validateElement(BIGNUM* el) {
	//A valid element in the grou pshould satisfy the following:
	//	1. 0 < el < p.
	//	2. el ^ q = 1 mod p.
	bool result = true;
	BIGNUM* p = dlog->p;

	//Check that the element is bigger than 0.
	BIGNUM* zero = BN_new();
	BN_zero(zero);
	if (BN_cmp(el, zero) <= 0) {
		result = false;
	}

	//Check that the element is smaller than p.
	if (BN_cmp(el, p) > 0) {
		result = false;
	}

	BIGNUM* q = dlog->q;
	BIGNUM* exp = BN_new();

	//Check that the element raised to q is 1 mod p.
	int suc = BN_mod_exp(exp, el, q, p, ctx);

	if (!BN_is_one(exp)) {
		result = false;
	}

	//Release the allocated memory.
	BN_free(zero);
	BN_free(exp);

	return result;
}

/*************************************************/
/**** OpenSSLDlogZpSafePrime ***/
/*************************************************/
OpenSSLDlogZpAdapter * OpenSSLDlogZpSafePrime::createOpenSSLDlogZpAdapter(biginteger p, biginteger q, biginteger g)
{
	// Create OpenSSL Dlog group with p, , q, g.
	// The validity of g will be checked after the creation of the group because the check need the pointer to the group
	DH * dh = DH_new();

	dh->p = biginteger_to_opensslbignum(p);
	dh->q = biginteger_to_opensslbignum(q);
	dh->g = biginteger_to_opensslbignum(g);
	if ((dh->p == NULL) || (dh->q == NULL) || (dh->g == NULL)) {
		DH_free(dh);
		throw runtime_error("failed to create OpenSSL Dlog group");
	}

	// Set up the BN_CTX.
	BN_CTX *ctx;
	if (NULL == (ctx = BN_CTX_new())) {
		DH_free(dh);
		throw runtime_error("failed to create OpenSSL Dlog group");
	}
	return new OpenSSLDlogZpAdapter(dh, ctx);
}

OpenSSLDlogZpAdapter * OpenSSLDlogZpSafePrime::createRandomOpenSSLDlogZpAdapter(int numBits) {
	DH * dh = DH_new();
	//Set up the BN_CTX.
	BN_CTX *ctx;
	if (NULL == (ctx = BN_CTX_new())) {
		DH_free(dh);
		return NULL;
	}

	//Seed the random geneartor.
#ifdef _WIN32
	RAND_screen(); // only defined for windows, reseeds from screen contents
#else
	RAND_poll(); // reseeds using hardware state (clock, interrupts, etc).
#endif

	//Sample a random safe prime with the requested number of bits.
	dh->p = BN_new();
	if (0 == (BN_generate_prime_ex(dh->p, numBits, 1, NULL, NULL, NULL))) {
		BN_CTX_free(ctx);
		DH_free(dh);
		return NULL;
	}

	//Calculates q from p, such that p = 2q + 1.
	dh->q = BN_new();
	if (0 == (BN_rshift1(dh->q, dh->p))) {
		BN_CTX_free(ctx);
		DH_free(dh);
		return 0;
	}

	//Sample a generator to the group. 
	//Each element in the group, except the identity, is a generator. 
	//The elements in the group are elements that have a quadratic residue modulus p.
	//Algorithm:
	//	g <- 0
	//	while g == 0 or g == 1:
	//		Sample a number between 0 to p, set it to g
	//		calculate g = g^2 nod p
	dh->g = BN_new();
	while (BN_is_zero(dh->g) || BN_is_one(dh->g)) {
		BN_rand_range(dh->g, dh->p);
		BN_mod_sqr(dh->g, dh->g, dh->p, ctx);
	}

	//Create a native Dlog object with dh and ctx.
	return new OpenSSLDlogZpAdapter(dh, ctx);
}

OpenSSLDlogZpSafePrime::OpenSSLDlogZpSafePrime(ZpGroupParams * groupParams, mt19937 prg)
{
	// TODO - unify with cryptoPP
	mt19937 prime_gen(clock()); // prg for prime checking
	biginteger p = groupParams->getP();
	biginteger q = groupParams->getQ();
	biginteger g = groupParams->getXg();

	if (!(q * 2 + 1 == p)) // if p is not 2q+1 throw exception
		throw invalid_argument("p must be equal to 2q+1");
	if (!miller_rabin_test(p, 40, prime_gen)) // if p is not a prime throw exception
		throw invalid_argument("p must be a prime");
	if (!miller_rabin_test(q, 40, prime_gen)) // if q is not a prime throw exception
		throw invalid_argument("q must be a prime");

	// set the inner parameters
	this->groupParams = groupParams;
	this->random_element_gen = prg;

	//Create a native Dlog object with dh and ctx.
	dlog = createOpenSSLDlogZpAdapter(p, q, g);

	//If the generator is not valid, delete the allocated memory and throw exception.
	if (!dlog->validateElement(dlog->getDlog()->g)) {
		delete dlog;
		throw new invalid_argument("generator value is not valid");
	}

	//Create the  generator with the pointer that return from the native function.
	generator = new OpenSSLZpSafePrimeElement(g, p, false);

	//Now that we have p, we can calculate k which is the maximum length of a string to be converted to a Group Element of this group.
	k = calcK(p);
}

OpenSSLDlogZpSafePrime::OpenSSLDlogZpSafePrime(int numBits, mt19937 prg) {

	this->random_element_gen = prg;

	// Create random Zp dlog group.
	dlog = createRandomOpenSSLDlogZpAdapter(numBits);
	// Get the generator value.
	biginteger pGenerator = opensslbignum_to_biginteger(dlog->getDlog()->g);

	//Create the GroupElement - generator with the pointer that returned from the native function.
	generator = new OpenSSLZpSafePrimeElement(pGenerator);

	//Get the generated parameters and create a ZpGroupParams object.
	biginteger p = opensslbignum_to_biginteger(dlog->getDlog()->p);
	biginteger q = opensslbignum_to_biginteger(dlog->getDlog()->q);
	biginteger xG = ((ZpElement *)generator)->getElementValue();
	groupParams = new ZpGroupParams(q, xG, p);

	//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
	k = calcK(p);

}

int OpenSSLDlogZpSafePrime::calcK(biginteger p) {
	int bitsInp = NumberOfBits(p);
	// Any string of length k has a numeric value that is less than (p-1)/2 - 1.
	int k = (bitsInp - 3) / 8;
	// The actual k that we allow is one byte less. This will give us an extra byte to pad the binary string passed to encode to a group element with a 01 byte
	// and at decoding we will remove that extra byte. This way, even if the original string translates to a negative BigInteger the encode and decode functions
	// always work with positive numbers. The encoding will be responsible for padding and the decoding will be responsible for removing the pad.
	k--;
	// For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
	// the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
	if (k > 255) {
		k = 255;
	}
	return k;
}

GroupElement * OpenSSLDlogZpSafePrime::getIdentity() {
	return new OpenSSLZpSafePrimeElement(1, ((ZpGroupParams *)groupParams)->getP(), false);
}

GroupElement * OpenSSLDlogZpSafePrime::createRandomElement() {
	return new OpenSSLZpSafePrimeElement(((ZpGroupParams*)groupParams)->getP(), random_element_gen);
}


bool OpenSSLDlogZpSafePrime::isMember(GroupElement * element) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(element);
	// check if element is ZpElementCryptoPp
	if (!zp_element)
		throw invalid_argument("type doesn't match the group type");
	biginteger element_value = zp_element->getElementValue();
	return dlog->validateElement(biginteger_to_opensslbignum(element_value));
}

bool OpenSSLDlogZpSafePrime::isGenerator() {
	return dlog->validateElement(dlog->getDlog()->g);
}

bool OpenSSLDlogZpSafePrime::validateGroup() {
	int result;
	// Run a check of the group.
	int suc = DH_check(dlog->getDlog(), &result);

	//In case the generator is 2, OpenSSL checks the prime is congruent to 11.
	//while the IETF's primes are congruent to 23 when g = 2. Without the next check, the IETF parameters would fail validation.
	if (BN_is_word(dlog->getDlog()->g, DH_GENERATOR_2))
	{
		long residue = BN_mod_word(dlog->getDlog()->p, 24);
		if (residue == 11 || residue == 23) {
			result &= ~DH_NOT_SUITABLE_GENERATOR;
		}
	}

	//In case the generator is not 2 or 5, openssl does not check it and returns result == 4 in DH_check function.
	//We check it directly.
	if (result == 4) {
		BIGNUM* g = dlog->getDlog()->g;
		result = !(dlog->validateElement(g));
	}

	return result == 0;
}

GroupElement * OpenSSLDlogZpSafePrime::getInverse(GroupElement * groupElement) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement);
	// check if element is ZpElementCryptoPp
	if (!zp_element)
		throw invalid_argument("type doesn't match the group type");

	DH* dh = dlog->getDlog();
	BIGNUM* result = BN_new();
	BIGNUM* elem = biginteger_to_opensslbignum(zp_element->getElementValue());
	BN_mod_inverse(result, elem, dh->p, dlog->getCTX());
	OpenSSLZpSafePrimeElement * inverseElement = new OpenSSLZpSafePrimeElement(opensslbignum_to_biginteger(result));

	BN_free(result);
	BN_free(elem);
	return inverseElement;
}

GroupElement * OpenSSLDlogZpSafePrime::exponentiate(GroupElement * base, biginteger exponent) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(base);
	// check if element is ZpElementCryptoPp
	if (!zp_element)
		throw invalid_argument("type doesn't match the group type");

	// call to native exponentiate function.
	DH* dh = dlog->getDlog();
	BIGNUM* expBN = biginteger_to_opensslbignum(exponent);
	BIGNUM* baseBN = biginteger_to_opensslbignum(zp_element->getElementValue());
	BIGNUM* resultBN = BN_new(); 	//Prepare a result element.

	//Raise the given element and put the result in result.
	BN_mod_exp(resultBN, baseBN, expBN, dh->p, dlog->getCTX());
	biginteger bi_res = opensslbignum_to_biginteger(resultBN);

	//Release the allocated memory.
	BN_free(expBN);
	BN_free(baseBN);
	BN_free(resultBN);

	// build an OpenSSLZpSafePrimeElement element with the result value.
	OpenSSLZpSafePrimeElement * exponentiateElement = new OpenSSLZpSafePrimeElement(bi_res);
	return exponentiateElement;
}

GroupElement * OpenSSLDlogZpSafePrime::multiplyGroupElements(GroupElement * groupElement1, GroupElement * groupElement2) {
	OpenSSLZpSafePrimeElement * zp1 = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement1);
	OpenSSLZpSafePrimeElement * zp2 = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement2);
	if (!zp1 || !zp2)
		throw invalid_argument("element type doesn't match the group type");

	// Call to native multiply function.
	DH* dh = dlog->getDlog();
	BIGNUM* result = BN_new();
	BIGNUM* elem1 = biginteger_to_opensslbignum(zp1->getElementValue());
	BIGNUM* elem2 = biginteger_to_opensslbignum(zp2->getElementValue());
	BN_mod_mul(result, elem1, elem2, dh->p, dlog->getCTX());
	OpenSSLZpSafePrimeElement * mulElement = new OpenSSLZpSafePrimeElement(opensslbignum_to_biginteger(result));

	BN_free(result);
	BN_free(elem1);
	BN_free(elem2);
	return mulElement;
}

GroupElement * OpenSSLDlogZpSafePrime::simultaneousMultipleExponentiations(vector<GroupElement *> groupElements, vector<biginteger> exponentiations) {
	for (int i = 0; i < groupElements.size(); i++) {
		OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElements[i]);
		if (!zp_element)
			throw invalid_argument("groupElement doesn't match the DlogGroup");
	}

	//currently, in cryptoPpDlogZpSafePrime the native algorithm is faster than the optimized one due to many calls to the JNI.
	//Thus, we operate the native algorithm. In the future we may change this.
	// TODO - THIS IS NOT TRUE ANYMORE. NEED TO FIX THIS.
	return computeNaive(groupElements, exponentiations);
}

GroupElement* OpenSSLDlogZpSafePrime::generateElement(bool bCheckMembership, vector<biginteger> values) {
	if (values.size() != 1)
		throw new invalid_argument("To generate an ZpElement you should pass the x value of the point");
	return new OpenSSLZpSafePrimeElement(values[0], ((ZpGroupParams *)groupParams)->getP(), bCheckMembership);
}

GroupElement* OpenSSLDlogZpSafePrime::reconstructElement(bool bCheckMembership, GroupElementSendableData * data) {
	ZpElementSendableData * zp_data = dynamic_cast<ZpElementSendableData *>(data);
	if (!zp_data)
		throw invalid_argument("groupElement doesn't match the group type");
	vector<biginteger> values = { zp_data->getX() };
	return generateElement(bCheckMembership, values);
}

OpenSSLDlogZpSafePrime::~OpenSSLDlogZpSafePrime()
{
	delete dlog;
}

GroupElement * OpenSSLDlogZpSafePrime::encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) {

	// any string of length up to k has numeric value that is less than (p-1)/2 - 1.
	// if longer than k then throw exception.
	int bs_size = binaryString.size();
	if (bs_size > k) {
		throw length_error("The binary array to encode is too long.");
	}

	//Pad the binaryString with a x01 byte in the most significant byte to ensure that the 
	//encoding and decoding always work with positive numbers.
	list<unsigned char> newString(binaryString.begin(), binaryString.end());
	newString.push_front(1);

	byte *bstr = new byte[bs_size + 1];
	for (auto it = newString.begin(); it != newString.end(); ++it) {
		int index = std::distance(newString.begin(), it);
		bstr[index] = *it;
	}
	biginteger s = decodeBigInteger(bstr, bs_size+1);
	delete(bstr);

	//Denote the string of length k by s.
	//Set the group element to be y=(s+1)^2 (this ensures that the result is not 0 and is a square)
	biginteger y = boost::multiprecision::powm((s + 1), 2, ((ZpGroupParams *)groupParams)->getP());

	//There is no need to check membership since the "element" was generated so that it is always an element.
	OpenSSLZpSafePrimeElement * element = new OpenSSLZpSafePrimeElement(y, ((ZpGroupParams *)groupParams)->getP(), false);
	return element;
}

const vector<byte> OpenSSLDlogZpSafePrime::decodeGroupElementToByteArray(GroupElement * groupElement) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement);
	if (!(zp_element))
		throw invalid_argument("element type doesn't match the group type");

	//Given a group element y, find the two inverses z,-z. Take z to be the value between 1 and (p-1)/2. Return s=z-1
	biginteger y = zp_element->getElementValue();
	biginteger p = ((ZpGroupParams *)groupParams)->getP();
	MathAlgorithms::SquareRootResults roots = MathAlgorithms::sqrtModP_3_4(y, p);

	biginteger goodRoot;
	biginteger halfP = (p - 1) / 2;
	if (roots.getRoot1()>1 && roots.getRoot1() < halfP)
		goodRoot = roots.getRoot1();
	else
		goodRoot = roots.getRoot2();
	goodRoot -= 1;

	int len = bytesCount(goodRoot);
	byte * output = new byte[len];
	encodeBigInteger(goodRoot, output, len);
	vector<byte> res;

	// Remove the padding byte at the most significant position (that was added while encoding)
	for (int i = 1; i < len; ++i)
		res.push_back(output[i]);
	return res;
}

const vector<byte> OpenSSLDlogZpSafePrime::mapAnyGroupElementToByteArray(GroupElement * groupElement) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement);
	if (!(zp_element))
		throw invalid_argument("element type doesn't match the group type");
	string res = string(zp_element->getElementValue());
	return vector<unsigned char>(res.begin(), res.end());
}