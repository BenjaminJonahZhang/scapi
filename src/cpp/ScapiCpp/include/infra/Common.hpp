#pragma once

#define WIN32_LEAN_AND_MEAN

#include <boost/random.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/timer/timer.hpp>
#include <math.h> /* pow */
#include <random>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <chrono>
#include "Log.hpp"

using namespace std;

class IllegalStateException : public logic_error
{
public:
	IllegalStateException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw(){ return "unacceptable state"; }
};

class NotImplementedException : public logic_error
{
public:
	NotImplementedException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw() { return "Function not yet implemented."; }
};

class InvalidKeyException : public logic_error
{
public:
	InvalidKeyException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw() { return "Invalid key"; }
};

// Using boost::multiprecision:mpz_int - Arbitrary precision integer type.
namespace mp = boost::multiprecision;     // Reduce the typing a bit later...
using biginteger = boost::multiprecision::cpp_int;

typedef unsigned char byte;		// put in global namespace to avoid ambiguity with other byte typedefs


int find_log2_floor(biginteger);
int NumberOfBits(biginteger bi);
size_t bytesCount(biginteger value);
mt19937 get_seeded_random();
void gen_random_bytes_vector(vector<byte> &v, const int len, mt19937 random = get_seeded_random());
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

void print_elapsed_ms(std::chrono::time_point<std::chrono::system_clock> start, string message);

std::chrono::time_point<std::chrono::system_clock> scapi_now();
