#include "Util.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

using namespace std;

void restoreKeys(block* receivedKeys, char* matrix, int n, int m, block* restoredKeys){

	block xorOfShares;
	for (int i = 0; i < n; i++) {
		
		xorOfShares = _mm_setzero_si128();

		for (int j = 0; j < m; j++) {

			if (0 == matrix[i*m+j]) {
				continue; // insignificant share
			}
			
			xorOfShares =  _mm_xor_si128(xorOfShares, receivedKeys[j]);
		}

		restoredKeys[i] = xorOfShares;		
	}	
}

/**
	* Gets a original keys and transform them into keys that corresponds to the matrix.
	* @param originalKeys The keys that matched the rows of the matrix.
	* @param mes used to generate new keys.
	* @return the transformed keys, that matched the columns of the matrix.
	*/
void transformKeys(block* originalKeys, block* probeResistantKeys, block* newKeys, int n, int m, char* matrix) {
	
	//For each pair of original keys allocate new keys and put them in the probeResistantKeys array.
	for (int i = 0; i < n; i++) {
		allocateKeys(probeResistantKeys, originalKeys[i*2], originalKeys[i*2+1], i, newKeys[i], m, matrix);
	}
}

void allocateKeys(block* probeResistantKeys, block originalKey0, block originalKey1, int i, block newKey, int m, char* matrix){
	//Get the delta between the keys.
	block delta = _mm_xor_si128(originalKey0, originalKey1);
	int shares = 0;
	int lastShare = 0;
	//Get the number of shares (the number of times that "1" is shows) of the row i in the matrix.
	// This might fail if the matrix is not probe resistant, with negligible probability.
	int res = getNumberOfShares(i, probeResistantKeys, m, matrix, &shares, &lastShare);
	if (res== 0){
		cout<<"error!!!"<<endl;
		return;
	}
	block zero = _mm_setzero_si128();
	block xorOfShares = originalKey0;
	for (int j = 0; j < m; j++) {
		if ((matrix[i*m+j] == 0) || (j == lastShare)) {
			// Skip on zeros and skip the last share.
			continue;
		}
			
		//Check if the keys are not set yet.
		if ((equalBlocks(probeResistantKeys[j*2],zero) == 0) &&
		   (equalBlocks(probeResistantKeys[j*2+1],zero) == 0) ){
			probeResistantKeys[j*2] = newKey;
			probeResistantKeys[j*2+1] = _mm_xor_si128(newKey, delta);
		}
			
		block key0 = probeResistantKeys[j*2];
		xorOfShares = _mm_xor_si128(xorOfShares, key0);
			
		shares--;
		if (0 == shares) {
			// All but the last share has been allocated
			break;
		}
	}
		
	//The last pair of keys are the xor of all shares and the xor of it with delta.
	probeResistantKeys[lastShare*2] = xorOfShares;
	probeResistantKeys[lastShare*2+1] = _mm_xor_si128(xorOfShares, delta);
}

/**
* Returns the number of times that the row i in the matrix contains "1".
* @param i The row in the matrix to get the shares of.
* @param probeResistantKeys The array of new keys.
* @param keySize The size of each key.
*/
int getNumberOfShares(int i, block* probeResistantKeys, int m, char* matrix, int* shares, int* lastShare) {
	bool allSharesAreAlreadyAssigned = true;
	block zero = _mm_setzero_si128();

	for (int j = 0; j < m; j++) {
		// Count the shares of bit i, and also try to find one that has not been assigned a key yet 
		// (otherwise we cannot complete the xor of all the keys).
		if (matrix[i*m+j] == 1) {
			(*shares)++;
				
			//Check if the keys are not set yet.
			if ((equalBlocks(probeResistantKeys[j*2],zero) == 0) &&
				(equalBlocks(probeResistantKeys[j*2+1],zero) == 0) ){
				allSharesAreAlreadyAssigned = false;
				*lastShare = j;
			}
		}
	}
		
	if (allSharesAreAlreadyAssigned) {
		return 0;
	}
	return 1;
}

bool equalBlocks(block a, block b)
{ 
	//A function that checks if two blocks are equal by casting to double size long array and check each half of a block
	long *ap = (long*) &a;
	long *bp = (long*) &b;
	if ((ap[0] == bp[0]) && (ap[1] == bp[1])){
		return 0;
	} else{
		return 1;
	}
}



void xorKeysWithMask(block* keys, block mask, int size){
	
	for (int i = 0; i < size; i++) {
		keys[i] =  _mm_xor_si128(keys[i], mask);
	}	
}

void xorKeys(block* keys1, block* keys2, block* output, int size){
	for (int i = 0; i < size; i++) {
		output[i] =  _mm_xor_si128(keys1[i], keys2[i]);
	}
}