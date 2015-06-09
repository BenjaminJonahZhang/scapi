// SCAPIGarbledCircuit.cpp : Defines the exported functions for the DLL application.
//


#ifdef _WIN32
	#include "StdAfx.h"
#else
	#include "Compat.h"
	#include <string.h>
#endif
#include "ScGarbledCircuit.h"
#include "RowReductionGarbledBooleanCircuit.h"
#include "StandardGarbledBooleanCircuit.h"
#include "FreeXorGarbledBooleanCircuit.h"
#include "HalfGatesGarbledBooleanCircuit.h"
#include <iostream>

using namespace std;


/* function createGarbledcircuit : This function creates a new circuit and returns a pointer to the created circuit. 
 * return			   : A pointer to the created circuit.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_createGarbledcircuit
(JNIEnv *env, jobject, jstring fileName, jint type, jboolean isNonXorOutputsRequired){

	const char* str = env->GetStringUTFChars(fileName, NULL);
	char *strFileName = (char*)str;

	GarbledBooleanCircuit *garbledCircuit = NULL;

	switch (type) {
	case 0:  
		garbledCircuit = new HalfGatesGarbledBooleanCircuit(str, isNonXorOutputsRequired);
		break;

	case 1:
		garbledCircuit = new RowReductionGarbledBooleanCircuit(str, isNonXorOutputsRequired);
		break;

	case 2:
		garbledCircuit = new FreeXorGarbledBooleanCircuit(str, isNonXorOutputsRequired);
		break;

	case 3:
		garbledCircuit = new StandardGarbledBooleanCircuit(str);
		break;
	default: 
		;
		break;
	}
	/*

	//create the relevant garbled circuit
	if (isTwoRows){
		garbledCircuit = new HalfGatesGarbledBooleanCircuit(str, isNonXorOutputsRequired);
	}

	else if (isRowReduction)
	{
		//The row reduction is allways with free xor
		garbledCircuit = new RowReductionGarbledBooleanCircuit(str, isNonXorOutputsRequired);

	}
	else{
		if (isFreeXor)
			garbledCircuit = new FreeXorGarbledBooleanCircuit(str, isNonXorOutputsRequired);
		else
			garbledCircuit = new StandardGarbledBooleanCircuit(str);

	}

	*/
	//release memory 
	env->ReleaseStringUTFChars(fileName, str);

	//return the pointer of the circuit. This will be saved in the java enviroment. Every access to the circuit, this pointer will
	//be sent from java.
	return (jlong)garbledCircuit;

}

/* function getOutputIndicesArray : This function returns the output indices array held in the circuit. 
 * return			: The output indices array
 */
JNIEXPORT jintArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_getOutputIndicesArray
  (JNIEnv * env, jobject, jlong gbcPtr){

	 //get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	//get the size of the output wire numbers
	int size= garbledCircuit->getNumberOfOutputs();

	//create a new jintArray with size number of outputs
	jintArray result = env->NewIntArray(size);

	//get the output indices from the native circuit to the newly create array
	env->SetIntArrayRegion(result, 0, size, (jint *)garbledCircuit->getOutputIndices());

	return result;


}
/* function getOutputIndicesArray : This function returns the input indices array held in the circuit. These indices are for all the parties
 *									One after the other.
 * return			: The input indices array
 */
JNIEXPORT jintArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_getInputIndicesArray
  (JNIEnv *env, jobject, jlong gbcPtr){

	 //get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	//get the size of the output wire numbers
	int size= garbledCircuit->getNumberOfInputs();

	//create a new jintArray with size number of inputs
	jintArray result = env->NewIntArray(size);

	//get the input indices from the native circuit to the newly create array
	env->SetIntArrayRegion(result, 0, size, (jint *)garbledCircuit->getInputIndices());

	return result;

}

/* function getOutputIndicesArray : This function returns the an array that holds for each party the number of inputs it has in the circuit.
 */
JNIEXPORT jintArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_getNumOfInputsForEachParty
  (JNIEnv *env, jobject, jlong gbcPtr){

	  //get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	//get the size of the output wire numbers
	int size= garbledCircuit->getNumberOfParties();

	//create a new jintArray with size number of parties
	jintArray result = env->NewIntArray(size);

	//get the array that holds for each party the number of inputs from the native circuit to the newly create array
	env->SetIntArrayRegion(result, 0, size, (jint *)garbledCircuit->getNumOfInputsForEachParty());

	return result;
}

/* function getTranslationTable : This function returns the translation table array of the circuit.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_getTranslationTable
  (JNIEnv *env, jobject, jlong gbcPtr){

	  //get the garbled circuit
	  GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	  //get the size of the output 
	  int size= (garbledCircuit->getNumberOfOutputs());

	  //create a jbyteArray with the size of the translation table
	  jbyteArray result = env->NewByteArray(size);

	  //copy the translation table of the native code to the result
	  env->SetByteArrayRegion(result, 0, size, (jbyte *)garbledCircuit->getTranslationTable());

	  return result;
}

/* function setTranslationTable : This function sets the translation table from java to the c++ garbled circuit.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_setTranslationTable
  (JNIEnv *env, jobject, jlong gbcPtr, jbyteArray translationTable){

	  //get the garbled circuit
	  GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	  //get the translation table as an array of jbyte
	  jbyte *carr = env->GetByteArrayElements(translationTable, 0);

	  //copy the translation table to the native circuit
	  memcpy( garbledCircuit->getTranslationTable(), carr, garbledCircuit->getNumberOfOutputs() );

	  
	  env->ReleaseByteArrayElements(translationTable,carr,JNI_ABORT);

}



/* function setTranslationTable : This function sets the garbled table from java to the c++ garbled circuit.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_setGarbleTables
  (JNIEnv *env, jobject, jlong gbcPtr, jbyteArray garbledTables){

	  //get the garbled circuit
	  GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	  int mult = 4;//for a regular circuit we have 4 blocks for each gate

	  if(garbledCircuit->getIsRowReduction()==true){

		  mult = 3;//in row reduction we only have 3 rows
	  }
	  else if (garbledCircuit->getIsTwoRows() == true){
		  mult = 2; //half gates only use 2 rows for AND gates
	  }

	   //get the garbled table as an array of jbyte
	  jbyte *carr = env->GetByteArrayElements(garbledTables, 0);

	  if (garbledCircuit->getIsNonXorOutputsRequired()){
		  //copy the garbled table to the native circuit
		  memcpy(garbledCircuit->getGarbledTables(), carr, ((garbledCircuit->getNumberOfGates() - garbledCircuit->getNumOfXorGates()) *mult + 2 * garbledCircuit ->getNumberOfOutputs())* 16);
	  }
	  else{
		  //copy the garbled table to the native circuit
		  memcpy(garbledCircuit->getGarbledTables(), carr, (garbledCircuit->getNumberOfGates() - garbledCircuit->getNumOfXorGates()) *mult * 16);

	  }
	   
	  //free the memory of jbyte array
	  env->ReleaseByteArrayElements(garbledTables,carr,JNI_ABORT);
}

/* function getGarbleTables : This function returns the garbled table array of the circuit.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_getGarbleTables
  (JNIEnv *env, jobject, jlong gbcPtr){

	 //get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	int mult = 4;//for a regular circuit we have 4 blocks for each gate

	if(garbledCircuit->getIsRowReduction()==true){

		mult = 3;//in row reduction we only have 3 rows
	}
	else if (garbledCircuit->getIsTwoRows() == true){
		mult = 2; //half gates only use 2 rows for AND gates
	}

	//get the size of the garbled table
	int size;
	if (garbledCircuit->getIsNonXorOutputsRequired()){
		size = (((garbledCircuit->getNumberOfGates() - garbledCircuit->getNumOfXorGates()) *mult + 2 * garbledCircuit->getNumberOfOutputs()) * 16);
	}
	else{
		size = ((garbledCircuit->getNumberOfGates() - garbledCircuit->getNumOfXorGates()) *mult * 16);
	}
	

	 //create a jbyteArray with the size of the garbled table
	jbyteArray result = env->NewByteArray(size);

	//copy the garbled table of the native code to the result
	env->SetByteArrayRegion(result, 0, size, (jbyte *)garbledCircuit->getGarbledTables());

	return result;

}
/* function garble : This function calls the garble of the native code garbled circuit that garbles the circuit.
 * It creates aligned memory for the inputs and outputs, and memory for the translation table so the native garble can work properly and eventually copies back
 * the results to the input empty arrays
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_garble
  (JNIEnv *env, jobject obj, jbyteArray allInputWireValues, jbyteArray allOutputWireValues, jbyteArray translationTable, jbyteArray seed, jlong gbcPtr){

	jbyte *jseed = env->GetByteArrayElements(seed, 0);
	 

	block seedBlock = _mm_set_epi8(jseed[15],jseed[14],jseed[13],jseed[12],jseed[11],jseed[10],jseed[9],jseed[8],jseed[7],jseed[6],jseed[5],jseed[4],jseed[3],jseed[2],jseed[1],jseed[0]);


	//get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit *)gbcPtr;
	jbyte *carr = env->GetByteArrayElements(translationTable, 0);


	//allocate memory for the input keys and the output keys and translation that will be filled by the native garble call
	block *inputs = (block *) _aligned_malloc(sizeof(block) *2 * garbledCircuit->getNumberOfInputs(), 16); 
	block *outputs = (block *) _aligned_malloc(sizeof(block) * 2 *garbledCircuit->getNumberOfOutputs(), 16); 
	
	garbledCircuit->garble(inputs, outputs, (unsigned char*)carr, seedBlock);
	
	//set all the information from the garble call back the empty arguments of this function
	env->SetByteArrayRegion(allInputWireValues, 0,sizeof(jbyte) *2 * garbledCircuit->getNumberOfInputs()*SIZE_OF_BLOCK ,  (jbyte*)inputs);
	env->SetByteArrayRegion(allOutputWireValues, 0,sizeof(jbyte) *2 * garbledCircuit->getNumberOfOutputs()*SIZE_OF_BLOCK ,  (jbyte*)outputs);
	
	//remove the memory that we have allocated in this function.
	_aligned_free(inputs);
	_aligned_free(outputs);
	//delete [] scTranslationTable;

	//release memory
	env->ReleaseByteArrayElements(translationTable,carr,0);
	env->ReleaseByteArrayElements(seed,jseed,JNI_ABORT);


	return 0;


}

/* function compute : This function calls the compute of the native code garbled circuit that computes the circuit.
 * It creates aligned memory for the inputs so the native compute can work properly and eventually get back the output
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_compute
(JNIEnv *env, jobject, jlong gbcPtr, jbyteArray singleInputs){

	//get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit = (GarbledBooleanCircuit *)gbcPtr;

	//get the single inputs as an array of jbyte
	jbyte *carr = env->GetByteArrayElements(singleInputs, 0);


	//allocate memory for the input keys and the output keys that will be filled
	block *inputs = (block *)_aligned_malloc(sizeof(block)  * garbledCircuit->getNumberOfInputs(), 16);
	block *outputs = (block *)_aligned_malloc(sizeof(block)  * garbledCircuit->getNumberOfOutputs(), 16);

	//create a jbyteArray with the size of the outputs
	jbyteArray outputKeys = env->NewByteArray(garbledCircuit->getNumberOfOutputs() * 16);

	int* intInputKeys = (int *)carr;
	jbyte* jbyteInputKeys = (jbyte *)singleInputs;

	//copy the bothInputKeys to the the aligned inputs
	memcpy(inputs, carr, garbledCircuit->getNumberOfInputs() * 16);

	if (garbledCircuit->getIsTwoRows() == true){
		((HalfGatesGarbledBooleanCircuit *)garbledCircuit)->compute(inputs, outputs);
	}
	else{
		//call the native function compute of the garbled circuit
		garbledCircuit->compute(inputs, outputs);
	}

	//copy the results from the native compute back the new array outputKeys.
	env->SetByteArrayRegion(outputKeys, 0, sizeof(jbyte) * garbledCircuit->getNumberOfOutputs() * 16, (jbyte*)outputs);


	//release the array for the singleInputs
	env->ReleaseByteArrayElements(singleInputs,carr,JNI_ABORT);

	//free dynamicallly allocated memory
	_aligned_free(outputs);
	_aligned_free(inputs);

	 return outputKeys;



}

/* function verify : This function calls the verify of the native code verify circuit that verifies the circuit.
 * It creates aligned memory for the inputs so the native verify can work properly and eventually get a true or false result
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_verify
  (JNIEnv *env, jobject, jlong gbcPtr, jbyteArray bothInputKeys){

	  //get the garbled circuit
	  GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit *)gbcPtr;

	  //allocate memory for the input keys and the output keys that will be filled
	  block *inputs = (block *) _aligned_malloc(sizeof(block) *2 * garbledCircuit->getNumberOfInputs(), 16); 
	 
	  //get the bothInputKeys as an array of jbyte
	  jbyte *carr = env->GetByteArrayElements(bothInputKeys, 0);

	  //copy the bothInputKeys to the the aligned inputs
	  memcpy( inputs, carr, garbledCircuit->getNumberOfInputs() *2 *16 );

	  //get the result of verify from the native circuit
	  bool isVerified = garbledCircuit->verify(inputs);

	  //release the memory
	  env->ReleaseByteArrayElements(bothInputKeys,carr,JNI_ABORT);

	  //free and inputs array
	  _aligned_free(inputs);

	  //now, after memory has been free return the value of the native verify call.
	  return isVerified;

}

/* function verify : This function calls the internalVerify of the native code internalVerifyof the circuit that internally verifies the circuit.
 * It creates aligned memory for the inputs so the native internalVerify can work properly and eventually get a true or false result
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_internalVerify
  (JNIEnv *env, jobject, jlong gbcPtr, jbyteArray bothInputKeys, jbyteArray emptyBothWireOutputKeys){

	  //get the garbled circuit
	  GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit *)gbcPtr;

	  //cout<< "in garble\n";

	  //allocate memory for the input keys and the output keys that will be filled
	  block *inputs = (block *) _aligned_malloc(sizeof(block) *2 * garbledCircuit->getNumberOfInputs(), 16); 
	  block *outputs = (block *) _aligned_malloc(sizeof(block) * 2 *garbledCircuit->getNumberOfOutputs(), 16); 

	  jbyte *carr = env->GetByteArrayElements(bothInputKeys, 0);

	  //copy the bothInputKeys to the the aligned inputs
	  memcpy( inputs, carr, garbledCircuit->getNumberOfInputs() *2 *16 );

	  //call the internal verify of the native circuit
	  bool isVerified = garbledCircuit->internalVerify(inputs,outputs);


	  //set the output from the native internal verify to the empty array of outputs received as argument
	  env->SetByteArrayRegion(emptyBothWireOutputKeys, 0,sizeof(jbyte) *2 * garbledCircuit->getNumberOfOutputs()*SIZE_OF_BLOCK ,  (jbyte*)outputs);

	  //release memory
	  env->ReleaseByteArrayElements(bothInputKeys,carr,JNI_ABORT);
	  _aligned_free(inputs);
	  _aligned_free(outputs);
	  
	  //now, after memory has been free return the value of the native internal verify call.
	  return isVerified;

}


/* function verifyTranslationTable : This function calls the verifyTranslationTable of the native code.
 * It creates aligned memory for the both outputs so the native verifyTranslationTable can work properly and eventually get a true or false result
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_verifyTranslationTable
	(JNIEnv *env, jobject, jlong gbcPtr, jbyteArray bothOutputKeys){


	bool result = false;


	//get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	jbyte *carr = env->GetByteArrayElements(bothOutputKeys, 0);
	
	//allocate memory for the output keys of both keys
	block *bothOutputResults = (block *) _aligned_malloc(sizeof(block)  * garbledCircuit->getNumberOfOutputs()*2, 16); 

	//copy the bothInputKeys to the the aligned inputs
	memcpy( bothOutputResults, carr, garbledCircuit->getNumberOfOutputs() *2 *16 );

	//call the native function
	result = garbledCircuit->verifyTranslationTable(bothOutputResults);

	//release the memory
	env->ReleaseByteArrayElements(bothOutputKeys,carr,JNI_ABORT);

	//now, after memory has been free return the value of the native verifyTranslationTable call.
	return result;



}

/* function translate : This function calls the verifyTranslationTable of the native code.
 * It creates aligned memory for the both outputs so the native verifyTranslationTable can work properly and eventually get a true or false result
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_translate
	(JNIEnv *env, jobject, jlong gbcPtr, jbyteArray outputKeys){

	
	
	//get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	unsigned char* answer = new unsigned char[garbledCircuit->getNumberOfOutputs()];

	jbyteArray answerJbytesArray = env->NewByteArray(garbledCircuit->getNumberOfOutputs());

	jbyte *carr = env->GetByteArrayElements(outputKeys, 0);
	
	//allocate memory for the input keys and the output keys that will be filled
	block *outputResults = (block *) _aligned_malloc(sizeof(block)  * garbledCircuit->getNumberOfOutputs(), 16); 

	//copy the outputKeys to the the aligned outputs
	memcpy( outputResults, carr, garbledCircuit->getNumberOfOutputs()  *16 );

	//get the answer of translate from the native circuit
	garbledCircuit->translate(outputResults, answer);

	//set the output from the native translate to the answer
	env->SetByteArrayRegion(answerJbytesArray, 0,sizeof(jbyte) * garbledCircuit->getNumberOfOutputs() ,  (jbyte*)answer);

	//relase memory
	env->ReleaseByteArrayElements(outputKeys,carr,JNI_ABORT);

	delete[] answer;

	//return the jbyteArray of the answer to translate
	return answerJbytesArray;

}
/* function verifyTranslate : This function calls the verifyTranslate of the native code.
 * It creates aligned memory for the single outputs as well as both outputs so the function can check that each element in the 
 * single array is either one key or the other. Only after this check we call the regual translate of the native circuit.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_verifyTranslate
	(JNIEnv *env, jobject, jlong gbcPtr, jbyteArray outputKeys , jbyteArray bothOutputKeys){


	jbyteArray answerJbytesArray;
	
	bool flagSuccess = true;

	//get the garbled circuit
	GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	unsigned char* answer = new unsigned char[garbledCircuit->getNumberOfOutputs()];

	jbyte *carrSingle = env->GetByteArrayElements(outputKeys, 0);
	jbyte *carrBoth = env->GetByteArrayElements(bothOutputKeys, 0);

	//allocate memory for the input keys and the output keys that will be filled
	block *singleOutputResultsBlocks = (block *) _aligned_malloc(sizeof(block)  * garbledCircuit->getNumberOfOutputs(), 16); 
	block *bothOutputKeysBlocks = (block *) _aligned_malloc(sizeof(block)  * garbledCircuit->getNumberOfOutputs()*2, 16); 


	//copy the outputKeys to the the aligned singleOutputResultsBlocks
	memcpy( singleOutputResultsBlocks, carrSingle, garbledCircuit->getNumberOfOutputs()  *16 );
	//copy the bothOutputKeys to the the aligned bothOutputKeysBlocks
	memcpy( bothOutputKeysBlocks, carrBoth, garbledCircuit->getNumberOfOutputs()*2  *16 );

	int numOfOutputs = garbledCircuit->getNumberOfOutputs();
	//check that the provided output keys are in fact one of 2 keys that we have
	for(int i=0; i<numOfOutputs ;i++)
	{
		if(!(garbledCircuit->equalBlocks(singleOutputResultsBlocks[i],bothOutputKeysBlocks[2*i]) || garbledCircuit->equalBlocks(singleOutputResultsBlocks[i],bothOutputKeysBlocks[2*i+1] ))){
			flagSuccess = false;
			break;
		}
	}

	if(flagSuccess==true){
		garbledCircuit->translate(singleOutputResultsBlocks, answer);

		//create an array for the answer to pass to java
		answerJbytesArray = env->NewByteArray(garbledCircuit->getNumberOfOutputs());
		//get the answer from the jbyte array answer returned by translate
		env->SetByteArrayRegion(answerJbytesArray, 0,sizeof(jbyte) * garbledCircuit->getNumberOfOutputs() ,  (jbyte*)answer);
		
	}	
	else{ //if the  check is false set the answer to null
		answerJbytesArray =NULL;
	}

	//release memory
	env->ReleaseByteArrayElements(outputKeys,carrSingle,JNI_ABORT);
	env->ReleaseByteArrayElements(bothOutputKeys,carrBoth,JNI_ABORT);
	
	//return true if each key is one of both possible keys and translate return true, false, otherwise.
	delete[] answer;
	return answerJbytesArray;

}


JNIEXPORT void JNICALL Java_edu_biu_scapi_circuits_fastGarbledCircuit_ScNativeGarbledBooleanCircuit_deleteCircuit
  (JNIEnv *, jobject, jlong gbcPtr ){

	  GarbledBooleanCircuit * garbledCircuit= (GarbledBooleanCircuit*) gbcPtr;

	  delete garbledCircuit;


}