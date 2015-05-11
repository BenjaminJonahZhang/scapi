#include <emmintrin.h>


typedef __m128i block;

#define SIZE_OF_BLOCK 16//size in bytes

void restoreKeys(block* receivedKeys, char* matrix, int n, int m, block* restoredKeys);

void xorKeysWithMask(block* keys, block mask, int size);

void xorKeys(block* keys1, block* keys2, block* output);

void transformKeys(block* originalKeys, block* probeResistantKeys, block* newKeys, int n, int m, char* matrix);

void allocateKeys(block* probeResistantKeys, block originalKey0, block originalKey1, int i, block newKey, int m, char* matrix);

int getNumberOfShares(int i, block* probeResistantKeys, int m, char* matrix, int*, int*);

bool equalBlocks(block a, block b);

