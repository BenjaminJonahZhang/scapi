#include "../ScapiCpp/include/primitives/DlogOpenSSL.hpp"
#include <boost/random.hpp>
#include <iostream>

int main20(){
	// initiate a discrete log group
	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
	DlogGroup * dlog = new OpenSSLDlogZpSafePrime(128);

	// get the group generator and order
	GroupElement * g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	// create a random exponent r
	mt19937 gen(get_seeded_random());
	boost::random::uniform_int_distribution<biginteger> ui(0, q - 1);
	biginteger r = ui(gen);

	// exponentiate g in r to receive a new group element
	GroupElement * g1 = dlog->exponentiate(g, r);
	// create a random group element
	GroupElement * h = dlog->createRandomElement();
	// multiply elements
	GroupElement * gMult = dlog->multiplyGroupElements(g1, h);

	cout << "genrator value is:              " << ((OpenSSLZpSafePrimeElement *)g)->getElementValue() << endl;
	cout << "exponentiate value is:          " << r << endl;
	cout << "exponentiation result is:       " << ((OpenSSLZpSafePrimeElement *)g1)->getElementValue() << endl;
	cout << "random element chosen is:       " << ((OpenSSLZpSafePrimeElement *)h)->getElementValue() << endl;
	cout << "element multplied by expresult: " << ((OpenSSLZpSafePrimeElement *)gMult)->getElementValue() << endl;
	return 0;
}

