#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "../include/catch.hpp"
#include "../include/Dlog.hpp"

TEST_CASE("Dlog get group type works", "[factorial]") {
	DlogGroup dg;
	REQUIRE(dg.getGroupType() == "no no");
}

TEST_CASE("test 2") {
	DlogGroup dg;
	REQUIRE(dg.getGroupType() != "n1o no");
}