#include <string>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/timer.hpp>
using namespace std;

class DlogGroup
{
public:
	virtual string getGroupType();
	virtual boost::multiprecision::int1024_t getOrder();
	virtual boost::timer some();
	DlogGroup();
};
