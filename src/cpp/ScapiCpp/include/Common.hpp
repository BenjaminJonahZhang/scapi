#ifndef SCAPI_COMMON_H
#define SCAPI_COMMON_H

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <boost/multiprecision/random.hpp>
#include <random>
#include <boost/multiprecision/miller_rabin.hpp>
#include <math.h> /* pow */
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

using namespace std;

class IllegalStateException : public logic_error
{
public:
	IllegalStateException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const { return "unacceptable state"; }
};

class NotImplementedException : public logic_error
{
public:
	NotImplementedException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const { return "Function not yet implemented."; }
};

class InvalidKeyException : public logic_error
{
public:
	InvalidKeyException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const { return "Invalid key"; }
};

// Using boost::multiprecision:mpz_int - Arbitrary precision integer type.
namespace mp = boost::multiprecision;     // Reduce the typing a bit later...
using biginteger = boost::multiprecision::cpp_int;

typedef unsigned char byte;		// put in global namespace to avoid ambiguity with other byte typedefs


int find_log2_floor(biginteger);
int NumberOfBits(biginteger bi);
size_t bytesCount(biginteger value);
void gen_random_bytes_vector(vector<byte> &v, const int len);
void copy_byte_vector_to_byte_array(const vector<byte> &source_vector, byte * dest, int beginIndex);
void copy_byte_array_to_byte_vector(const byte* src, int src_len, vector<byte>& target_vector, int beginIndex);
/*
* Converting big integer to a byte array. Array must be allocated already
*/
void encodeBigInteger(biginteger value, byte* output, size_t length);
biginteger decodeBigInteger(byte* input, size_t length);
/*
* Converting big integer to a byte array. Allocate a new array and returns it. make sure to free it!
* Returns the array size
*/
size_t allocateAndEncodeBigInteger(biginteger value, byte * output);

biginteger convert_hex_to_biginteger(const string & hex);

string hexStr(vector<byte> const & data);

#endif