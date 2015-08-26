#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "../include/catch.hpp"
#include "../include/Dlog.hpp"
#include "../include/DlogCryptopp.h"


// Test helper functions 

TEST_CASE("find_log2_floor is correct", "[find_log2_floor]") {
	REQUIRE(find_log2_floor(16) == 4);
	REQUIRE(find_log2_floor(19) == 4);
	REQUIRE(find_log2_floor(31) == 4);
	REQUIRE(find_log2_floor(32) == 5);
	REQUIRE(find_log2_floor(39) == 5);
}

TEST_CASE("boosts multiprecision stuff", "[factorial]") {
	biginteger res = mp::pow(biginteger(2), 10);
	REQUIRE(res == 1024);

	boost::mt19937 gen(clock());
	bool res_80 = mp::miller_rabin_test(80, 40, gen);
	bool res_71 = mp::miller_rabin_test(71, 40, gen);
	REQUIRE(!res_80);
	REQUIRE(res_71);

	boost::random::uniform_int_distribution<biginteger> ui(0, 100);
	for (int i = 0; i < 10; ++i) {
		biginteger randNum = ui(gen);
		REQUIRE((randNum >= 1 && randNum <= 100));
	}
	// 16 is 1000 - bit index is starting to count right to left so:
	bool bit_4 = mp::bit_test(16, 4);
	bool bit_0 = mp::bit_test(16, 0);
	REQUIRE(bit_4);
	REQUIRE(!bit_0);

	// Test that casting to string works
	string s = "12345678910123456789";
	biginteger bi(s);
	REQUIRE(bi == 12345678910123456789);
	REQUIRE((string)bi == "12345678910123456789");

	// Test boost::powm
	REQUIRE(mp::powm(2, 3, 3) == 2);
	REQUIRE(mp::powm(3, 4, 17) == 13);


	//Test conversion between CryptoPP::Integer and boost's biginteger
	//small Biginteger -> CryptoPP:Integer and back
	biginteger p(123);
	CryptoPP::Integer cp = biginteger_to_cryptoppint(p);
	REQUIRE(cp.ConvertToLong() == 123);
	REQUIRE(cp == 123);
	REQUIRE(cryptoppint_to_biginteger(cp) == p);

	// Big Biginteger -> CryptoPP:Integer and back
	string s2 = "12345678910111212313230983204932509435098230498230948723509234098234098234098234098234098230498234098";
	biginteger p2(s2);
	CryptoPP::Integer cp2 = biginteger_to_cryptoppint(p2);
	REQUIRE(!cp2.IsConvertableToLong());
	REQUIRE(cryptoppint_to_biginteger(cp2) == p2);

	// Big CryptoPP -> biginteger and back
	CryptoPP::Integer cp3(s2.c_str());
	biginteger p3 = cryptoppint_to_biginteger(cp3);
	REQUIRE(!cp3.IsConvertableToLong());
	REQUIRE(p3.str()==s2);
	REQUIRE(biginteger_to_cryptoppint(p3) == cp3);
}

TEST_CASE("CryptoPpDlogZpSafePrime", "[CryptoPpDlogZpSafePrime]")
{
	DlogGroup * dg = new CryptoPpDlogZpSafePrime(64); // testing with the default 1024 take too much time. 64 bit is good enough to test conversion with big numbers
	GroupElement * ge = dg->createRandomElement();
	GroupElement * ige = dg->getInverse(ge);
	GroupElement * mul = dg->multiplyGroupElements(ge, ige);
	GroupElement * identity = dg->getIdentity();

	vector <GroupElement *> vs {ge, ige, mul, identity };
	for(GroupElement * tge: vs)
		REQUIRE(dg->isMember(tge));

	REQUIRE(mul->isIdentity());
	delete dg, ge, ige, mul, identity;
}

// TEST all the stuff in MathAlgorithms
