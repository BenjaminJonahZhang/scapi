#include "MaliciousYaoUtil.h"
#include "TedKrovetzAesNiWrapperC.h"
#include <iostream>


using namespace std;

JNIEXPORT void JNICALL Java_edu_biu_protocols_yao_primitives_KProbeResistantMatrix_restoreKeys
  (JNIEnv *env, jobject, jbyteArray receivedKeysArray, jobjectArray matrixArray, int n, int m, jbyteArray restoredKeysArray){

	  block* receivedKeys = (block *)  _mm_malloc(sizeof(block) * m, 16);
	  block* restoredKeys = (block *)  _mm_malloc(sizeof(block) * n, 16);
	  
	  jbyte *carr = env->GetByteArrayElements(receivedKeysArray, 0);
	  memcpy(receivedKeys, carr, sizeof(block) * m);

	  char* matrix = new char[n*m];

	  for (int i=0; i<n; i++){
		  
		 jbyteArray matrixRowArray = (jbyteArray) env->GetObjectArrayElement(matrixArray, i);
		 jbyte* matrixRow  = (jbyte*) env->GetByteArrayElements(matrixRowArray, 0);
		 
		 memcpy(matrix+i*m, matrixRow, m);
		   
		 env->ReleaseByteArrayElements(matrixRowArray,matrixRow,JNI_ABORT);
	  }
	  
	  restoreKeys(receivedKeys, matrix, n, m, restoredKeys);
	 
	  env->SetByteArrayRegion(restoredKeysArray, 0, n*SIZE_OF_BLOCK,  (jbyte*)restoredKeys);

	  env->ReleaseByteArrayElements(receivedKeysArray,carr,JNI_ABORT);
	  _mm_free(receivedKeys);
	  _mm_free(restoredKeys);

	  delete matrix;

}

JNIEXPORT void JNICALL Java_edu_biu_protocols_yao_primitives_KProbeResistantMatrix_transformKeys
  (JNIEnv *env, jobject, jbyteArray originalKeysBytes, jbyteArray probeResistantKeysBytes, jbyteArray seedBytes, int n, int m, jobjectArray matrixArray){
	  
	  jbyte *originalKeys = env->GetByteArrayElements(originalKeysBytes, 0);
	  jbyte *probeResistantKeys = env->GetByteArrayElements(probeResistantKeysBytes, 0);
	  jbyte *seed = env->GetByteArrayElements(seedBytes, 0);

	  block* originalKeysb = (block *)  _mm_malloc(sizeof(block) * n * 2, 16);
	  block* probeResistantKeysb = (block *)  _mm_malloc(sizeof(block) * m * 2, 16);
	  block* newKeysb = (block *)  _mm_malloc(sizeof(block) * n, 16);
	  block * indexArray = (block *)_mm_malloc(sizeof(block) * n, 16);
	
	  for (int i = 0; i < n; i++){

		indexArray[i] = _mm_set_epi32(0, 0, 0, i);
	  }

	  AES_KEY * aesSeedKey = (AES_KEY *)_mm_malloc(sizeof(AES_KEY), 16);
	  AES_set_encrypt_key((const unsigned char *)seed, 128, aesSeedKey);
	  AES_ecb_encrypt_chunk_in_out(indexArray, newKeysb, n, aesSeedKey);

	  memcpy(originalKeysb, originalKeys, sizeof(block) *  n * 2);
	  memcpy(probeResistantKeysb, probeResistantKeys, sizeof(block) *  m * 2);
	  
	  char* matrix = new char[n*m];

	  for (int j=0; j<n; j++){
		  
		 jbyteArray matrixRowArray = (jbyteArray) env->GetObjectArrayElement(matrixArray, j);
		 jbyte* matrixRow  = (jbyte*) env->GetByteArrayElements(matrixRowArray, 0);
		 
		 memcpy(matrix+j*m, matrixRow, m);
		   
		 env->ReleaseByteArrayElements(matrixRowArray,matrixRow,JNI_ABORT);
	  }

	  transformKeys(originalKeysb, probeResistantKeysb, newKeysb, n, m, matrix);
	  
	  memcpy(probeResistantKeys, (jbyte*)probeResistantKeysb, sizeof(block) *  m * 2);
	 
	  env->ReleaseByteArrayElements(probeResistantKeysBytes,probeResistantKeys,0);
	 env->ReleaseByteArrayElements(originalKeysBytes,originalKeys,0);
	 env->ReleaseByteArrayElements(seedBytes,seed,0);

	 _mm_free(originalKeysb);
	 _mm_free(probeResistantKeysb);
	 _mm_free(newKeysb);
	 _mm_free(indexArray);
	 _mm_free(aesSeedKey);

	 delete matrix;
}

JNIEXPORT void JNICALL Java_edu_biu_protocols_yao_primitives_KProbeResistantMatrix_allocateKeys
  (JNIEnv *env, jobject, jbyteArray probeResistantKeysBytes, jbyteArray originalKey0Bytes, jbyteArray originalKey1Bytes, 
  int i, jbyteArray newKeyBytes, int n, int m, jobjectArray matrixArray){
	  
	  block* probeResistantKeys = (block *)  _mm_malloc(sizeof(block) * m * 2, 16);
	  
	  jbyte *carr = env->GetByteArrayElements(probeResistantKeysBytes, 0);
	  jbyte *key0 = env->GetByteArrayElements(originalKey0Bytes, 0);
	  jbyte *key1 = env->GetByteArrayElements(originalKey1Bytes, 0);
	  jbyte *newKey = env->GetByteArrayElements(newKeyBytes, 0);
	  
	  block originalKey0 =  _mm_set_epi8(key0[15], key0[14], key0[13], key0[12], key0[11], key0[10], key0[9], key0[8], key0[7], key0[6], key0[5], key0[4], key0[3], key0[2], key0[1], key0[0]);
	  block originalKey1 =  _mm_set_epi8(key1[15], key1[14], key1[13], key1[12], key1[11], key1[10], key1[9], key1[8], key1[7], key1[6], key1[5], key1[4], key1[3], key1[2], key1[1], key1[0]);
	  block newKeyb =  _mm_set_epi8(newKey[15], newKey[14], newKey[13], newKey[12], newKey[11], newKey[10], newKey[9], newKey[8], newKey[7], newKey[6], newKey[5], newKey[4], newKey[3], newKey[2], newKey[1], newKey[0]);
	  
	  memcpy(probeResistantKeys, carr, sizeof(block) *  m * 2);

	  char* matrix = new char[n*m];

	  for (int j=0; j<n; j++){
		  
		 jbyteArray matrixRowArray = (jbyteArray) env->GetObjectArrayElement(matrixArray, j);
		 jbyte* matrixRow  = (jbyte*) env->GetByteArrayElements(matrixRowArray, 0);
		 
		 memcpy(matrix+j*m, matrixRow, m);
		   
		 env->ReleaseByteArrayElements(matrixRowArray,matrixRow,JNI_ABORT);
	  }
	  allocateKeys(probeResistantKeys, originalKey0, originalKey1, i, newKeyb, m, matrix);
	 
	  memcpy(carr, (jbyte*)probeResistantKeys, sizeof(block) *  m * 2);

	  env->ReleaseByteArrayElements(probeResistantKeysBytes,carr,0);
	  env->ReleaseByteArrayElements(originalKey0Bytes, (jbyte*)key0, JNI_ABORT);
	  env->ReleaseByteArrayElements(originalKey1Bytes, (jbyte*)key1, JNI_ABORT);
	  env->ReleaseByteArrayElements(newKeyBytes, (jbyte*) newKey, JNI_ABORT);

	  _mm_free(probeResistantKeys);

	  delete matrix;
}

JNIEXPORT void JNICALL Java_edu_biu_protocols_yao_offlineOnline_specs_OnlineProtocolP2_xorKeysWithMask
  (JNIEnv *env, jobject, jbyteArray keysArray, jbyteArray maskBytes, int size){

	  block* keysBlocks = (block *)  _mm_malloc(sizeof(block) * size, 16);
	 
	  jbyte *keys = env->GetByteArrayElements(keysArray, 0);
	  jbyte *maskArray = env->GetByteArrayElements(maskBytes, 0);
	  
	  memcpy(keysBlocks, keys, sizeof(block) * size);
	   
	  block mask;
	  memcpy(&mask, maskArray, sizeof(block));
	 
	  for (int i = 0; i < size; i++) {
		keysBlocks[i] =  _mm_xor_si128(keysBlocks[i], mask);
	}

	  env->ReleaseByteArrayElements(keysArray,keys,JNI_ABORT);
	  env->ReleaseByteArrayElements(maskBytes,maskArray,JNI_ABORT);

	  env->SetByteArrayRegion(keysArray, 0, size*SIZE_OF_BLOCK,  (jbyte*)keysBlocks);

	   _mm_free(keysBlocks);

}


JNIEXPORT void JNICALL Java_edu_biu_protocols_yao_offlineOnline_specs_OnlineProtocolP2_xorKeys
  (JNIEnv * env, jobject, jbyteArray keys1Array, jbyteArray keys2Array, jbyteArray output, int size){
	  
	  block* keys1Blocks = (block *)  _mm_malloc(sizeof(block) * size, 16);
	  block* keys2Blocks = (block *)  _mm_malloc(sizeof(block) * size, 16);
	  block* outputBlocks = (block *)  _mm_malloc(sizeof(block) * size, 16);
	 
	  jbyte *keys1 = env->GetByteArrayElements(keys1Array, 0);
	  jbyte *keys2 = env->GetByteArrayElements(keys2Array, 0);
	  
	  memcpy(keys1Blocks, keys1, sizeof(block) * size);
	  memcpy(keys2Blocks, keys2, sizeof(block) * size);
	   
	  for (int i = 0; i < size; i++) {
		outputBlocks[i] =  _mm_xor_si128(keys1Blocks[i], keys2Blocks[i]);
	}

	  env->ReleaseByteArrayElements(keys1Array,keys1,JNI_ABORT);
	  env->ReleaseByteArrayElements(keys1Array,keys2,JNI_ABORT);

	  env->SetByteArrayRegion(output, 0, size*SIZE_OF_BLOCK,  (jbyte*)outputBlocks);

	   _mm_free(keys2Blocks);
	   _mm_free(outputBlocks);
}


JNIEXPORT bool JNICALL Java_edu_biu_protocols_yao_offlineOnline_specs_OnlineProtocolP2_verifyDecommitment
	(JNIEnv * env, jobject, jbyteArray commitment, jbyteArray rArray, jbyteArray xArray){

		jbyte *comm = env->GetByteArrayElements(commitment, 0);
		jbyte *r = env->GetByteArrayElements(rArray, 0);
		jbyte *x = env->GetByteArrayElements(xArray, 0);

		SHA_CTX sha;
		
		int rounds = env->GetArrayLength(xArray)/SIZE_OF_BLOCK;
		int hashSize = env->GetArrayLength(rArray)/rounds;

		char* output = new char[hashSize];
		
		for (int j=0; j<rounds; j++){
			SHA1_Init(&sha);
			SHA1_Update(&sha, r+j*hashSize, hashSize);
			SHA1_Update(&sha, x+j*SIZE_OF_BLOCK, SIZE_OF_BLOCK);
			SHA1_Final((unsigned char*) output, &sha);
			
			bool equal = true;
			for (int i=0; i<hashSize; i++){
				if (output[i] != (comm+j*hashSize)[i]){
					cout<<"not equal. j = "<<j<< endl;
					delete output;
					env->ReleaseByteArrayElements(commitment,comm,JNI_ABORT);
					env->ReleaseByteArrayElements(rArray,r,JNI_ABORT);
					env->ReleaseByteArrayElements(xArray,x,JNI_ABORT);

					return false;
				}
			}
		}

		delete output;
		env->ReleaseByteArrayElements(commitment,comm,JNI_ABORT);
		env->ReleaseByteArrayElements(rArray,r,JNI_ABORT);
		env->ReleaseByteArrayElements(xArray,x,JNI_ABORT);

		return true;
}

