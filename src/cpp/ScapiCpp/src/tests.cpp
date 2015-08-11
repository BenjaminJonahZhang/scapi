#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "../include/catch.hpp"
#include "../include/Dlog.hpp"

TEST_CASE("Factorials are computed", "[factorial]") {
	DlogGroup dg;
	REQUIRE(dg.getGroupType() == "no no");
}

TEST_CASE("Factorials are computed2", "[factorial]") {
	DlogGroup dg;
	REQUIRE(dg.getOrder() == 3);
}