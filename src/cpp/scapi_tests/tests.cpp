#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include "../ScapiCpp/include/infra/Common.hpp"
#include "catch.hpp"
#include "../ScapiCpp/include/primitives/Dlog.hpp"
#include "../ScapiCpp/include/primitives/DlogCryptopp.hpp"
#include "../ScapiCpp/include/primitives/DlogOpenSSL.hpp"
#include "../ScapiCpp/include/primitives/HashOpenSSL.hpp"
#include "../ScapiCpp/include/primitives/PrfOpenSSL.hpp"
#include "../ScapiCpp/include/primitives/TrapdoorPermutationOpenSSL.hpp"
#include "../ScapiCpp/include/primitives/Prg.hpp"
#include "../ScapiCpp/include/primitives/Kdf.hpp"
#include "../ScapiCpp/include/primitives/RandomOracle.hpp"
#include "../ScapiCpp/include/comm/TwoPartyComm.hpp"
#include <ctype.h>

biginteger endcode_decode(biginteger bi) {
	size_t len = bytesCount(bi);
	byte * output = new byte[len];
	encodeBigInteger(bi, output, len);
	auto res = decodeBigInteger(output, len);
	delete output;
	return res;
}

string rsa100 = "1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139";

TEST_CASE("Common methods", "[boost, common, math, log, bitLength, helper]") {

	SECTION("find_log2_floor") {
		REQUIRE(find_log2_floor(16) == 4);
		REQUIRE(find_log2_floor(19) == 4);
		REQUIRE(find_log2_floor(31) == 4);
		REQUIRE(find_log2_floor(32) == 5);
		REQUIRE(find_log2_floor(39) == 5);
	}

	SECTION("bitlength and byteLength")
	{
		REQUIRE(NumberOfBits(64) == 7);
		REQUIRE(bytesCount(64) == 1);
		REQUIRE(NumberOfBits(9999) == 14);
		REQUIRE(bytesCount(9999) == 2);
		REQUIRE(NumberOfBits(biginteger(rsa100))== 330);
		REQUIRE(bytesCount(biginteger(rsa100)) == 42);
		REQUIRE(NumberOfBits(-biginteger(rsa100)) == 330);
		REQUIRE(bytesCount(-biginteger(rsa100)) == 42);
	}

	SECTION("gen_random_bytes_vector")
	{
		vector<byte> v, v2;
		gen_random_bytes_vector(v, 10);
		gen_random_bytes_vector(v2, 10);
		REQUIRE(v.size() == 10);
		for (byte b : v)
			REQUIRE(isalnum(b));
		string string1(v.begin(), v.end());
		string string2(v2.begin(), v2.end());
		REQUIRE(string1 != string2);
	}

	SECTION("copy byte vector to byte array")
	{
		vector<byte> v;
		gen_random_bytes_vector(v, 20);
		byte * vb = new byte[40];
		int index;
		copy_byte_vector_to_byte_array(v, vb, 0);
		copy_byte_vector_to_byte_array(v, vb, 20);
		for (auto it = v.begin(); it != v.end(); it++)
		{
			index = it - v.begin();
			REQUIRE(*it == vb[index]);
			REQUIRE(*it == vb[index+20]);
		}
		delete vb;
	}


	SECTION("copy byte array to byte vector")
	{
		byte src[10] = { 0xb1, 0xb2, 0xb3, 0xb4,  0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xc1 };
		vector<byte> target;
		copy_byte_array_to_byte_vector(src, 10, target, 0);
		int i = 0;
		REQUIRE(target.size() == 10);
		for (byte & b : target) 
			REQUIRE(src[i++] == b);
		target.clear();
		copy_byte_array_to_byte_vector(src, 10, target, 5);
		i = 5;
		REQUIRE(target.size() == 5);
		for (byte & b : target)
			REQUIRE(src[i++] == b);
	}

	SECTION("encode and decode bigintegers")
	{
		biginteger bi_res = endcode_decode(3322);
		REQUIRE(bi_res == 3322);
		biginteger birsa100 = biginteger(rsa100);
		bi_res = endcode_decode(birsa100);
		REQUIRE(bi_res == birsa100);
		bi_res = endcode_decode(-birsa100);
		REQUIRE(bi_res == -birsa100);
	}

	SECTION("convert hex to string") {
		string hex = "64";
		REQUIRE(convert_hex_to_biginteger(hex)==biginteger(100));
	}
}

TEST_CASE("boosts multiprecision", "[boost, multiprecision]") {

	mt19937 gen(get_seeded_random());

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
		for (int i = 0; i < 100; ++i) {
			biginteger randNum = ui(gen);
			REQUIRE((randNum >= 0 && randNum <= 100));
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
		REQUIRE(MathAlgorithms::factorial(6)==720);
		string fact35 = "10333147966386144929666651337523200000000";
		REQUIRE(MathAlgorithms::factorialBI(35).str() == fact35);
	}
}

/***************************************************/
/***********TESTING DLOG IMPLEMENTATIONS******************/
/*****************************************************/

void test_multiply_group_elements(DlogGroup * dg, bool check_membership=false)
{
	GroupElement * ge = dg->createRandomElement();
	GroupElement * ige = dg->getInverse(ge);
	GroupElement * mul = dg->multiplyGroupElements(ge, ige);
	GroupElement * identity = dg->getIdentity();

	vector <GroupElement *> vs{ ge, ige, mul, identity };
	if (check_membership)
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
	gen_random_bytes_vector(v, k);

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
		//delete dg;
	}
	SECTION("test OpenSSLZpSafePrime implementation")
	{
		DlogGroup * dg = new OpenSSLDlogZpSafePrime(64); // testing with the default 1024 take too much time. 64 bit is good enough to test conversion with big numbers
		test_all(dg);
	}
}

template<typename T>
void test_hash(string in, string expect)
{
	CryptographicHash * hash = new T();
	const char *cstr = in.c_str();
	int len = in.size();
	vector<byte> vec(cstr, cstr + len);
	hash->update(vec, 0, len);
	vector<byte> out;
	hash->hashFinal(out, 0);
	string actual = hexStr(out);
	CAPTURE(actual);
	CAPTURE(expect);
	CAPTURE(actual.size());
	CAPTURE(expect.size());
	CAPTURE(hash->getHashedMsgSize());
	REQUIRE(actual == expect);
	delete hash;
}

TEST_CASE("Hash", "[HASH, SHA1]")
{
	SECTION("Testing OpenSSL SHA1") {
		string input_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		test_hash<OpenSSLSHA1>(input_msg, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
		test_hash<OpenSSLSHA224>(input_msg, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
		test_hash<OpenSSLSHA256>(input_msg, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
		test_hash<OpenSSLSHA384>(input_msg, "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
		test_hash<OpenSSLSHA512>(input_msg, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
	}
}

template<typename T>
void test_prp(string key, string in, string expected_out)
{
	OpenSSLPRP * prp = new T();
	string s = boost::algorithm::unhex(key);
	char const *c = s.c_str();
	SecretKey sk = SecretKey((byte *)c, strlen(c), prp->getAlgorithmName());
	prp->setKey(sk);

	string sin = boost::algorithm::unhex(in);
	char const * cin = sin.c_str();
	vector<byte> in_vec, out_vec;
	copy_byte_array_to_byte_vector((byte*)cin, strlen(cin), in_vec, 0);
	prp->computeBlock(in_vec, 0, out_vec, 0);
	
	REQUIRE(hexStr(out_vec) == expected_out);
	delete prp;
}

TEST_CASE("PRF", "[AES, PRF]")
{
	SECTION("OpenSSL PRP")
	{
		test_prp<OpenSSLAES>("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97");
	}
	SECTION("TRIPLE DES")
	{
		string key = "1234567890123456ABCDEFGH";
		string plain = "The quic";
		test_prp<OpenSSLTripleDES>(boost::algorithm::hex(key), boost::algorithm::hex(plain), "13d4d3549493d287");
	}
	SECTION("HMAC")
	{
		string key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
		char const * plain = "Hi There";
		string expected_out_hex = "b617318655057264e28bc0b6fb378c8ef146be00";

		// create mac and set key
		auto mac = new OpenSSLHMAC();
		string s = boost::algorithm::unhex(key);
		char const *c = s.c_str();
		SecretKey sk = SecretKey((byte *)c, strlen(c), mac->getAlgorithmName());
		mac->setKey(sk);

		// compute_block for plain 
		int in_len = strlen(plain);
		vector<byte> in_vec, out_vec;
		copy_byte_array_to_byte_vector((byte*)plain, in_len, in_vec, 0);
		mac->computeBlock(in_vec, 0, in_len, out_vec, 0);

		// clean 
		delete mac;
		
		// verify 
		REQUIRE(hexStr(out_vec) == expected_out_hex);
	}
}

void test_prg(PseudorandomGenerator * prg, string expected_name)
{
	REQUIRE(!prg->isKeySet()); // verify key is not set yet
	auto sk = prg->generateKey(32);
	prg->setKey(sk);
	REQUIRE(prg->isKeySet());

	REQUIRE(prg->getAlgorithmName() == expected_name); // verify alg name is as expected
	vector<byte> out;
	prg->getPRGBytes(out, 0, 16);
	REQUIRE(out.size() == 16);
	vector<byte> out2;
	prg->getPRGBytes(out2, 0, 16);
	string s1(out.begin(), out.end());
	string s2(out2.begin(), out2.end());
	REQUIRE(s1 != s2);
}

TEST_CASE("PRG", "[PRG]")
{
	SECTION("ScPrgFromPrf")
	{
		PseudorandomFunction * prf = new OpenSSLAES();
		ScPrgFromPrf * scprg = new ScPrgFromPrf(prf);
		test_prg(scprg, "PRG_from_AES");
	}

	SECTION("OpenSSLRC4")
	{
		test_prg(new OpenSSLRC4(), "RC4");
	}
}

TEST_CASE("KDF","")
{
	SECTION("HKDF")
	{
		HKDF hkdf(new OpenSSLHMAC());
		string s = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
		string source = boost::algorithm::unhex(s);
		vector<byte> v_source(source.begin(), source.end());
		auto sk = hkdf.deriveKey(v_source, 0, v_source.size(), 40);
		auto v = sk.getEncoded();
		string s2(v.begin(), v.end());
	}
}

void random_oracle_test(RandomOracle * ro, string algName)
{
	REQUIRE(ro->getAlgorithmName() == algName);
	string input = "123456";
	vector<byte> in_vec(input.begin(), input.end());
	vector<byte> output;
	ro->compute(in_vec, 0, 6, output, 6);
	//REQUIRE(output.size() == 6);
	string s(output.begin(), output.end());
	delete ro;
}
TEST_CASE("Random Oracle", "")
{
	SECTION("HashBasedRO") {
		random_oracle_test(new HashBasedRO(), "HashBasedRO");
	}
	SECTION("HKDFBasedRO") {
		HKDF hkdf(new OpenSSLHMAC());
		random_oracle_test(new HKDFBasedRO(&hkdf), "HKDFBasedRO");
	}
}

TEST_CASE("TrapdoorPermutation", "[OpenSSL]")
{
	SECTION("OpenSSL") {
		auto tp = OpenSSLRSAPermutation();
		REQUIRE(tp.getAlgorithmName() == "OpenSSLRSA");
		biginteger public_mod = 55;
		int public_exponent = 3;
		int private_exponent = 7;
		tp.setKey(new RSAPublicKey(public_mod, public_exponent), new RSAPrivateKey(public_mod, private_exponent));
		RSAElement * re_src = (RSAElement *) tp.generateRandomTPElement();
		auto re_enc = tp.compute(re_src);
		auto re_inv = tp.invert(re_enc);
		CAPTURE(re_enc->getElement());
		REQUIRE(re_inv->getElement() == re_src->getElement());
	}
}

TEST_CASE("Comm basics", "[Communication]") {
	SECTION("Comparing SocketPartyData") {
		auto spd1 = SocketPartyData(IpAdress::from_string("127.0.0.1"), 3000);
		auto spd2 = SocketPartyData(IpAdress::from_string("127.0.0.1"), 3001);
		REQUIRE(spd1 < spd2);
		REQUIRE(spd2 > spd1);
		REQUIRE(spd2 >= spd1);
		REQUIRE(spd1 <= spd2);
		REQUIRE(spd1 != spd2);
		REQUIRE(!(spd1 == spd2));
	}
	SECTION("connect") {
		SocketPartyData sp1(IpAdress::from_string("127.0.0.1"), 3000);
		SocketPartyData sp2(IpAdress::from_string("62.210.18.40"), 5201);
		//NativeChannel nc(&sp1, &sp2);
		//nc.connect();
		//Message m(new byte[4]{ '1', '2', '3', '4' }, 4);
		//nc.send(m);
	}
}