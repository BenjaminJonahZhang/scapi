#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "../include/catch.hpp"
#include "../include/Dlog.hpp"


// Test helper functions 

TEST_CASE("find_log2_floor is correct", "[find_log2_floor]") {
	REQUIRE(find_log2_floor(16) == 4);
	REQUIRE(find_log2_floor(19) == 4);
	REQUIRE(find_log2_floor(31) == 4);
	REQUIRE(find_log2_floor(32) == 5);
	REQUIRE(find_log2_floor(39) == 5);
}

TEST_CASE("boosts multiprecision stuff", "[factorial]") {
	biginteger res = boost::multiprecision::pow(biginteger(2), 10);
	REQUIRE(res == 1024);

	boost::mt19937 gen(clock());
	bool res_80 = boost::multiprecision::miller_rabin_test(80, 40, gen);
	bool res_71 = boost::multiprecision::miller_rabin_test(71, 40, gen);
	REQUIRE(!res_80);
	REQUIRE(res_71);

	boost::random::uniform_int_distribution<biginteger> ui(0, 100);
	for (int i = 0; i < 10; ++i) {
		biginteger randNum = ui(gen);
		REQUIRE((randNum >= 1 && randNum <= 100));
	}
	// 16 is 1000 bit index is starting to cound right to left so:
	bool bit_4 = boost::multiprecision::bit_test(16, 4);
	bool bit_0 = boost::multiprecision::bit_test(16, 0);
	REQUIRE(bit_4);
	REQUIRE(!bit_0);

	// Test that casting to string works

	// Test boost::powm

	// Test conversion between CryptoPP::Integer and boost's biginteger
}

