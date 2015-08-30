#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "../include/catch.hpp"
#include "../include/Dlog.hpp"
#include "../include/DlogCryptopp.h"


void gen_random(vector<unsigned char> &v, const int len) {
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		v.push_back(alphanum[rand() % (sizeof(alphanum) - 1)]);
	}
}

TEST_CASE("find_log2_floor", "[helper, log, bitcount]") {
	REQUIRE(find_log2_floor(16) == 4);
	REQUIRE(find_log2_floor(19) == 4);
	REQUIRE(find_log2_floor(31) == 4);
	REQUIRE(find_log2_floor(32) == 5);
	REQUIRE(find_log2_floor(39) == 5);
}

TEST_CASE("boosts multiprecision", "[boost, multiprecision]") {

	boost::mt19937 gen(clock());

	SECTION("testing pow")
	{
		biginteger res = mp::pow(biginteger(2), 10);
		REQUIRE(res == 1024);
	}

	SECTION("miller rabin test for prime numbers")
	{
		bool res_80 = mp::miller_rabin_test(80, 70, gen);
		bool res_71 = mp::miller_rabin_test(71, 70, gen);
		REQUIRE(!res_80);
		REQUIRE(res_71);
	}

	SECTION("generating random from range")
	{
		boost::random::uniform_int_distribution<biginteger> ui(0, 100);
		for (int i = 0; i < 10; ++i) {
			biginteger randNum = ui(gen);
			REQUIRE((randNum >= 1 && randNum <= 100));
		}
	}
	
	SECTION("bit test")
	{
		// 16 is 1000 - bit index is starting to count right to left so:
		bool bit_4 = mp::bit_test(16, 4);
		bool bit_0 = mp::bit_test(16, 0);
		REQUIRE(bit_4);
		REQUIRE(!bit_0);
	}

	SECTION("string conversion for biginteger")
	{
		string s = "12345678910123456789123456789123456789123456789123456789123456789123456789123456789";
		biginteger bi(s);
		REQUIRE((string)bi == s);
		REQUIRE(bi.str()  == s);
		biginteger b2 = bi - 3;
		auto st_res = s.substr(0, s.size() - 1)+"6";
		REQUIRE(b2.str() == st_res);
	}

	SECTION("boost powm - pow modolu m")
	{
		REQUIRE(mp::powm(2, 3, 3) == 2);
		REQUIRE(mp::powm(3, 4, 17) == 13);
	}

	SECTION("conversion between CryptoPP::Integer and boost's biginteger")
	{
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
		REQUIRE(p3.str() == s2);
		REQUIRE(biginteger_to_cryptoppint(p3) == cp3);
	}

	SECTION("sqrt and sqrt with reminder")
	{
		REQUIRE(mp::sqrt(25) == 5);
		REQUIRE(mp::sqrt(27) == 5);
		biginteger r;
		auto res = mp::sqrt(biginteger(25), r);
		REQUIRE(r == 0);
		REQUIRE(res == 5);
		auto res = mp::sqrt(biginteger(29), r);
		REQUIRE(r == 4);
		REQUIRE(res == 5);
	}
}

TEST_CASE("MathAlgorithm", "[crt, sqrt_mod_3_4, math]")
{
	SECTION("conversion between CryptoPP::Integer and boost's biginteger")
	{
		// sqrt(16) mod 7 == (4,-4)
		MathAlgorithms::SquareRootResults roots = MathAlgorithms::sqrtModP_3_4(16, 7);
		REQUIRE((roots.getRoot1() == 4 || roots.getRoot2() == 4));

		// sqrt(25) mod 7 == (5,-5)
		roots = MathAlgorithms::sqrtModP_3_4(25, 7);
		REQUIRE((roots.getRoot1() == 5 || roots.getRoot2() == 5));

		// sqrt(121) mod 7 == (4,-4)
		roots = MathAlgorithms::sqrtModP_3_4(121, 7);
		REQUIRE((roots.getRoot1() == 4 || roots.getRoot2() == 4));

		// sqrt(207936) mod 7 == (1,-1)
		roots = MathAlgorithms::sqrtModP_3_4(207936, 7);
		REQUIRE((roots.getRoot1() == 1 || roots.getRoot2() == 1));

		// 13 is equal to 3 mod 4
		REQUIRE_THROWS_AS(MathAlgorithms::sqrtModP_3_4(625, 13), invalid_argument);
	}
	SECTION("mod inverse")
	{
		biginteger res = MathAlgorithms::modInverse(3, 7);
		REQUIRE(res == 5);
	}
	SECTION("Chineese reminder theorem")
	{
		vector<biginteger> congruences = { 2, 3, 2 };
		vector<biginteger> moduli = { 3, 5, 7 };
		auto bi= MathAlgorithms::chineseRemainderTheorem(congruences, moduli);
		REQUIRE(bi == 23);
	}
	SECTION("factorial")
	{
		REQUIRE(MathAlgorithms::factorial(6), 720);
		string fact35 = "10333147966386144929666651337523200000000";
		REQUIRE(MathAlgorithms::factorialBI(35).str() == fact35);
	}
}

/***************************************************/
/***********TESTING DLOG IMPLEMENTATIONS******************/
/*****************************************************/

void test_multiply_group_elements(DlogGroup * dg)
{
	GroupElement * ge = dg->createRandomElement();
	GroupElement * ige = dg->getInverse(ge);
	GroupElement * mul = dg->multiplyGroupElements(ge, ige);
	GroupElement * identity = dg->getIdentity();

	vector <GroupElement *> vs{ ge, ige, mul, identity };
	for (GroupElement * tge : vs)
		REQUIRE(dg->isMember(tge));

	REQUIRE(mul->isIdentity());
	delete ge, ige, mul, identity;
}

void test_exponentiate(DlogGroup * dg)
{
	GroupElement * ge = dg->createRandomElement();
	GroupElement * res_exp = dg->exponentiate(ge, 3);
	GroupElement * res_mul = dg->multiplyGroupElements(dg->multiplyGroupElements(ge, ge), ge);
	REQUIRE(*res_exp == *res_mul); // testing the == operator overloading and override
	delete ge, res_exp, res_mul;
}

void test_simultaneous_multiple_exponentiations(DlogGroup * dg)
{
	GroupElement * ge1 = dg->createRandomElement();
	GroupElement * ge2 = dg->createRandomElement();

	vector<GroupElement *> baseArray = { ge1, ge2 };
	vector<biginteger> exponentArray = { 3, 4 };

	GroupElement * res1 = dg->simultaneousMultipleExponentiations(baseArray, exponentArray);
	GroupElement * expected_res = dg->multiplyGroupElements(dg->exponentiate(ge1, 3),
		dg->exponentiate(ge2, 4));

	REQUIRE(*res1 == *expected_res);
	delete ge1, ge2, res1, expected_res;
}

void test_exponentiate_with_pre_computed_values(DlogGroup * dg)
{
	GroupElement * base = dg->createRandomElement();
	GroupElement * res = dg->exponentiateWithPreComputedValues(base, 32);
	GroupElement * expected_res = dg->exponentiate(base, 32);
	dg->endExponentiateWithPreComputedValues(base);

	REQUIRE(*expected_res == *res);
	delete base, res, expected_res;
}

void test_encode_decode(DlogGroup * dg)
{
	int k = dg->getMaxLengthOfByteArrayForEncoding();
	REQUIRE(k > 0);

	vector<byte> v;
	v.reserve(k);
	gen_random(v, k);

	GroupElement * ge = dg->encodeByteArrayToGroupElement(v);
	vector<byte> res = dg->decodeGroupElementToByteArray(ge);

	for (int i = 0; i < k; i++)
		REQUIRE(v[i] == res[i]);
}

void test_all(DlogGroup * dg)
{
	test_multiply_group_elements(dg);
	test_simultaneous_multiple_exponentiations(dg);
	test_exponentiate(dg);
	test_exponentiate_with_pre_computed_values(dg);
	test_encode_decode(dg);
}

TEST_CASE("DlogGroup", "[Dlog, DlogGroup, CryptoPpDlogZpSafePrime]")
{
	SECTION("testing CryptoPpDlogZpSafePrime implemenation")
	{
		DlogGroup * dg = new CryptoPpDlogZpSafePrime(64); // testing with the default 1024 take too much time. 64 bit is good enough to test conversion with big numbers
		test_all(dg);
		delete dg;
	}
}



/// TEST EC Utilities!
