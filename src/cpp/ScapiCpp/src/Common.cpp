#include "../include/Common.hpp"

/******************************/
/* Helper Methods *************/
/******************************/

int find_log2_floor(biginteger bi) {
	int r = 0;
	while (bi >>= 1) // unroll for more speed...
		r++;
	return r;
}

int NumberOfBits(biginteger bi) {
	return find_log2_floor(bi) + 1;
}

void gen_random_bytes_vector(vector<byte> &v, const int len) {
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) 
		v.push_back(alphanum[rand() % (sizeof(alphanum) - 1)]);
}

/**
* Copies all byte from source vector to dest starting from some index in dest.
* Assuming dest is already initialized.
*/
void copy_byte_vector_to_byte_array(const vector<byte> &source_vector, byte * dest, int beginIndex) {
	for (auto it = source_vector.begin(); it != source_vector.end(); ++it) {
		int index = std::distance(source_vector.begin(), it) + beginIndex;
		dest[index] = *it;
	}
}

/*
* Length of biginteger in bytes
*/
size_t bytesCount(biginteger value)
{
	if (value.is_zero())
		return 1;
	if (value.sign() < 0)
		value = ~value;
	size_t length = 0;
	byte lastByte;
	do {
		lastByte = value.convert_to<byte>();
		value >>= 8;
		length++;
	} while (!value.is_zero());
	if (lastByte >= 0x80)
		length++;
	return length;
}

void encodeBigInteger(biginteger value, byte* output, size_t length)
{
	if (value.is_zero())
		*output = 0;
	else if (value.sign() > 0)
		while (length-- > 0) {
			*(output++) = value.convert_to<byte>();
			value >>= 8;
		}
	else {
		value = ~value;
		while (length-- > 0) {
			*(output++) = ~value.convert_to<byte>();
			value >>= 8;
		}
	}
}

biginteger decodeBigInteger(byte* input, size_t length)
{
	biginteger result(0);
	int bits = -8;
	while (length-- > 1)
		result |= (biginteger) *(input++) << (bits += 8);
	byte a = *(input++);
	result |= (biginteger) a << (bits += 8);
	if (a >= 0x80)
		result |= (biginteger) - 1 << (bits + 8);
	return result;
}

size_t allocateAndEncodeBigInteger(biginteger value, byte * output) {
	size_t len = bytesCount(value);
	output = new byte[len];
	encodeBigInteger(value, output, len);
	return len;
}

biginteger convert_hex_to_biginteger(const string & input) {
	string s = "0x" + input;
	return boost::lexical_cast<biginteger>(s);
}
