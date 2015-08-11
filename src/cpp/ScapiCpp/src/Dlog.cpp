#include <iostream>
#include "../include/Dlog.hpp"

using namespace std;

string DlogGroup::getGroupType()
{
	return "no no";
}

boost::timer DlogGroup::some()
{
	return boost::timer();
}

boost::multiprecision::int1024_t DlogGroup::getOrder()
{
	return boost::multiprecision::int1024_t();
}

DlogGroup::DlogGroup(void)
{
	cout << "creating Group";
}
