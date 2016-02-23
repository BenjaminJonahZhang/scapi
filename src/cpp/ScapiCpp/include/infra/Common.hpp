#pragma once

#define WIN32_LEAN_AND_MEAN

#include <boost/random.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/timer/timer.hpp>
#include <math.h> /* pow */
#include <random>
#include <memory>
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
};

class NotImplementedException : public logic_error
{
public:
	NotImplementedException(const string & msg) : logic_error(msg) {};
};

class InvalidKeyException : public logic_error
{
public:
	InvalidKeyException(const string & msg) : logic_error(msg) {};
};

// using boost::multiprecision:cpp_int - Arbitrary precision integer type.
namespace mp = boost::multiprecision;     // reduce the typing a bit later...
using biginteger = boost::multiprecision::cpp_int;

typedef unsigned char byte;		// put in global namespace to avoid ambiguity with other byte typedefs


int find_log2_floor(biginteger);
int NumberOfBits(biginteger bi);

/*
* Retruns the number of bytes needed to represent a biginteger
* Notice that due to the sign number of byte can exceed log(value)
*/
size_t bytesCount(biginteger value);

mt19937 get_seeded_random();
mt19937_64 get_seeded_random64();
void gen_random_bytes_vector(vector<byte> &v, const int len, mt19937 random = get_seeded_random());
void copy_byte_vector_to_byte_array(const vector<byte> &source_vector, byte * dest, int beginIndex);
void copy_byte_array_to_byte_vector(const byte* src, int src_len, vector<byte>& target_vector, int beginIndex);
/*
* Converting big integer to a byte array. Array must be allocated already
* Number can be postive or negative - the sign will be preserved in the encoding
* Use byteCount(biginteger) method to calculate the number of bytes needed.
*/
void encodeBigInteger(biginteger value, byte* output, size_t length);

/*
* Decodoing big integer from byte array back to a biginteger object
*/
biginteger decodeBigInteger(byte* input, size_t length);

biginteger convert_hex_to_biginteger(const string & hex);

string hexStr(vector<byte> const & data);

void print_elapsed_ms(std::chrono::time_point<std::chrono::system_clock> start, string message);

std::chrono::time_point<std::chrono::system_clock> scapi_now();

/*
* Returns a random biginteger uniformly distributed in [min, max]
*/
biginteger getRandomInRange(biginteger min, biginteger max, std::mt19937 random);
void print_byte_array(byte * arr, int len, string message);
/**
* Abstract market interface that allow serialization and deserialization from byte array and size
*/
class NetworkSerialized {
public:
	virtual int getSerializedSize() = 0;
	virtual shared_ptr<byte> toByteArray() = 0;
	virtual void initFromByteArray(byte* arr, int size) = 0;
	virtual void initFromByteVector(vector<byte> * byteVectorPtr) {
		initFromByteArray(&(byteVectorPtr->at(0)), byteVectorPtr->size());
	}
};


