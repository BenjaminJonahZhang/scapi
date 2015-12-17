#pragma once

#include "../../include/circuits/FastGarbledBooleanCircuit.hpp"

/*******************************************/
/* ScNativeGarbledBooleanCircuitNoFixedKey */
/*******************************************/
ScNativeGarbledBooleanCircuitNoFixedKey::ScNativeGarbledBooleanCircuitNoFixedKey(string fileName, bool isFreeXor) {
	//create the relevant garbled circuit
	if (isFreeXor) 
		garbledCircuitPtr = new FastGarblingFreeXorHalfGatesFixedKeyAssumptions(fileName.c_str());
	else 
		//the best implementation for non free xor is the 4 to 2 
		garbledCircuitPtr = new FastGarblingFourToTwoNoAssumptions(fileName.c_str());
}

/**
* Not used in this implementation since we require a seed for optimization concerns
*/
FastCircuitCreationValues ScNativeGarbledBooleanCircuitNoFixedKey::garble() {
	byte * seed = new byte[16];
	if (!RAND_bytes(seed, 16))
		throw runtime_error("key generation failed");
	return garble(seed);
}

FastCircuitCreationValues ScNativeGarbledBooleanCircuitNoFixedKey::garble(byte* seed) {
	byte* allInputWireValues = new byte[garbledCircuitPtr->getNumberOfInputs()*SCAPI_NATIVE_KEY_SIZE * 2];
	byte* allOutputWireValues = new byte[garbledCircuitPtr->getNumberOfOutputs()*SCAPI_NATIVE_KEY_SIZE * 2];
	byte* translationTable = new byte[garbledCircuitPtr->getNumberOfOutputs()];

	block seedBlock = _mm_set_epi8(seed[15], seed[14], seed[13], seed[12], seed[11], seed[10], seed[9], seed[8],
		seed[7], seed[6], seed[5], seed[4], seed[3], seed[2], seed[1], seed[0]);

	garbledCircuitPtr->garble((block *)allInputWireValues, (block *)allOutputWireValues, translationTable, seedBlock);
	FastCircuitCreationValues outputVal = FastCircuitCreationValues(allInputWireValues, allOutputWireValues, translationTable);
	return outputVal;
}

byte* ScNativeGarbledBooleanCircuitNoFixedKey::getGarbledInputFromUngarbledInput(
	byte* ungarbledInputBits, byte * allInputWireValues, int partyNumber) {
	int startingIndex = 0;
	for (int i = 0; i < partyNumber - 1; i++)
		startingIndex += getNumberOfInputs(i);
	int numberOfInputsForThisParty = getNumberOfInputs(partyNumber - 1);

	byte* result = new byte[SCAPI_NATIVE_KEY_SIZE*numberOfInputsForThisParty];
	int destBeginIndex, sourceBeginIndex;
	for (int i = 0; i< numberOfInputsForThisParty; i++)
		if (ungarbledInputBits[i] == 0) {
			sourceBeginIndex = (i + startingIndex) * 2 * SCAPI_NATIVE_KEY_SIZE;
			destBeginIndex = i*SCAPI_NATIVE_KEY_SIZE;
			memcpy(result + destBeginIndex, allInputWireValues + sourceBeginIndex, SCAPI_NATIVE_KEY_SIZE);
		}
		else {
			sourceBeginIndex = ((i + startingIndex) * 2 + 1)*SCAPI_NATIVE_KEY_SIZE;
			destBeginIndex = i*SCAPI_NATIVE_KEY_SIZE;
			memcpy(result + destBeginIndex, allInputWireValues + sourceBeginIndex, SCAPI_NATIVE_KEY_SIZE);
		}
		return result;
}

byte* ScNativeGarbledBooleanCircuitNoFixedKey::compute() {
	if (garbledInputs.size() / 16 != garbledCircuitPtr->getNumberOfInputs())
		throw NotAllInputsSetException("missing inputs");
	
	// allocate memory for the input keys and the output keys that will be filled
	block *inputs = (block *)_aligned_malloc(sizeof(block)  * garbledCircuitPtr->getNumberOfInputs(), 16);
	block *outputs = (block *)_aligned_malloc(sizeof(block)  * garbledCircuitPtr->getNumberOfOutputs(), 16);
	
	// copy the bothInputKeys to the the aligned inputs
	memcpy(inputs, &garbledInputs[0], garbledCircuitPtr->getNumberOfInputs() * 16);

	// call the native function compute of the garbled circuit
	garbledCircuitPtr->compute(inputs, outputs);
	byte * result = new byte[garbledCircuitPtr->getNumberOfOutputs() * 16];
	memcpy(result, outputs, garbledCircuitPtr->getNumberOfOutputs() * 16);

	// free dynamicallly allocated memory
	_aligned_free(outputs);
	_aligned_free(inputs);

	return result;
}

bool ScNativeGarbledBooleanCircuitNoFixedKey::verify(byte* allInputWireValues) {
	//allocate memory for the input keys and the output keys that will be filled
	block *inputs = (block *)_aligned_malloc(sizeof(block) * 2 * garbledCircuitPtr->getNumberOfInputs(), 16);
	//copy the bothInputKeys to the the aligned inputs
	memcpy(inputs, allInputWireValues, garbledCircuitPtr->getNumberOfInputs() * 2 * 16);
	//get the result of verify from the native circuit
	bool isVerified = garbledCircuitPtr->verify(inputs);
	//free and inputs array
	_aligned_free(inputs);

	//now, after memory has been free return the value of the native verify call.
	return isVerified;
}

bool ScNativeGarbledBooleanCircuitNoFixedKey::internalVerify(byte * allInputWireValues, byte* allOutputWireValues) {
	//allocate memory for the input keys and the output keys that will be filled
	block *inputs = (block *)_aligned_malloc(sizeof(block) * 2 * garbledCircuitPtr->getNumberOfInputs(), 16);
	block *outputs = (block *)_aligned_malloc(sizeof(block) * 2 * garbledCircuitPtr->getNumberOfOutputs(), 16);
	//copy the bothInputKeys to the the aligned inputs
	memcpy(inputs, allInputWireValues, garbledCircuitPtr->getNumberOfInputs() * 2 * 16);
	//call the internal verify of the native circuit
	bool isVerified = garbledCircuitPtr->internalVerify(inputs, outputs);
	//set the output from the native internal verify to the empty array of outputs received as argument
	memcpy(allOutputWireValues, outputs, 2 * garbledCircuitPtr->getNumberOfOutputs()*SIZE_OF_BLOCK);
	_aligned_free(inputs);
	_aligned_free(outputs);

	return isVerified;
}

byte* ScNativeGarbledBooleanCircuitNoFixedKey::translate(byte * garbledOutput) {
	byte* answer = new byte[garbledCircuitPtr->getNumberOfOutputs()];
	//allocate memory for the input keys and the output keys that will be filled
	block *outputResults = (block *)_aligned_malloc(sizeof(block)  * garbledCircuitPtr->getNumberOfOutputs(), 16);
	//copy the outputKeys to the the aligned outputs
	memcpy(outputResults, garbledOutput, garbledCircuitPtr->getNumberOfOutputs() * 16);
	// get the answer of translate from the native circuit
	garbledCircuitPtr->translate(outputResults, answer);
	//set the output from the native translate to the answer
	return answer;
}

byte* ScNativeGarbledBooleanCircuitNoFixedKey::verifyTranslate(byte* garbledOutput, byte* bothOutputKeys) {
	bool flagSuccess = true;
	byte* answer = new byte[garbledCircuitPtr->getNumberOfOutputs()];
	//allocate memory for the input keys and the output keys that will be filled
	block *singleOutputResultsBlocks = (block *)_aligned_malloc(sizeof(block)  * garbledCircuitPtr->getNumberOfOutputs(), 16);
	block *bothOutputKeysBlocks = (block *)_aligned_malloc(sizeof(block)  * garbledCircuitPtr->getNumberOfOutputs() * 2, 16);
	//copy the outputKeys to the the aligned singleOutputResultsBlocks
	memcpy(singleOutputResultsBlocks, garbledOutput, garbledCircuitPtr->getNumberOfOutputs() * 16);
	//copy the bothOutputKeys to the the aligned bothOutputKeysBlocks
	memcpy(bothOutputKeysBlocks, bothOutputKeys, garbledCircuitPtr->getNumberOfOutputs() * 2 * 16);
	int numOfOutputs = garbledCircuitPtr->getNumberOfOutputs();
	//check that the provided output keys are in fact one of 2 keys that we have
	for (int i = 0; i<numOfOutputs; i++)
	{
		if (!(garbledCircuitPtr->equalBlocks(singleOutputResultsBlocks[i], bothOutputKeysBlocks[2 * i]) || 
			garbledCircuitPtr->equalBlocks(singleOutputResultsBlocks[i], bothOutputKeysBlocks[2 * i + 1]))) {
			flagSuccess = false;
			break;
		}
	}

	if (flagSuccess) {
		garbledCircuitPtr->translate(singleOutputResultsBlocks, answer);
	}
	else { //if the  check is false set the answer to null
		delete[] answer;
		answer = NULL;
	}
	return answer;
}

GarbledTablesHolder * ScNativeGarbledBooleanCircuitNoFixedKey::getGarbledTables() {
	int size = 0;
	if (garbledCircuitPtr->getIsFreeXor()) {
		size = (garbledCircuitPtr->getNumberOfGates() - garbledCircuitPtr->getNumOfXorGates() - garbledCircuitPtr->getNumOfNotGates()) * 2 * 16;
	}
	else {
		size = (((garbledCircuitPtr->getNumberOfGates() - garbledCircuitPtr->getNumOfXorGates() - garbledCircuitPtr->getNumOfNotGates()) * 33) / 16
			+ 1 + garbledCircuitPtr->getNumOfXorGates()) * 16;
	}
	byte * garbledTables = (byte*)garbledCircuitPtr->getGarbledTables();
	return new JustGarbledGarbledTablesHolder(garbledTables, size);
}

void ScNativeGarbledBooleanCircuitNoFixedKey::setGarbledTables(GarbledTablesHolder * garbledTables) {
	int size = 0;
	if (garbledCircuitPtr->getIsFreeXor())
		size = (garbledCircuitPtr->getNumberOfGates() - garbledCircuitPtr->getNumOfXorGates() - garbledCircuitPtr->getNumOfNotGates()) * 2 * 16;
	else 
		size = (((garbledCircuitPtr->getNumberOfGates() - garbledCircuitPtr->getNumOfXorGates() - garbledCircuitPtr->getNumOfNotGates()) * 33) / 16 + 1 + garbledCircuitPtr->getNumOfXorGates()) * 16;
	//copy the garbled table to the native circuit
	memcpy(garbledCircuitPtr->getGarbledTables(), garbledTables->toDoubleByteArray()[0], size);
}

int* ScNativeGarbledBooleanCircuitNoFixedKey::getInputWireIndices(int partyNumber) {
	int startingIndex = 0;
	for (int i = 0; i<partyNumber - 1; i++)
		startingIndex += getNumberOfInputs(i);
	int numberOfInputsForThisParty = getNumberOfInputs(partyNumber - 1);
	int* result = new int[numberOfInputsForThisParty];
	// copy the relevant key of the input into the result array.
	auto inputsIndices = garbledCircuitPtr->getInputIndices();
	memcpy(result, &inputsIndices[startingIndex], numberOfInputsForThisParty);
	return result;
}

bool ScNativeGarbledBooleanCircuitNoFixedKey::verifyTranslationTable(byte* allOutputWireValues) {
	bool result = false;
	//allocate memory for the output keys of both keys
	block *bothOutputResults = (block *)_aligned_malloc(sizeof(block) * garbledCircuitPtr->getNumberOfOutputs() * 2, 16);
	//copy the bothInputKeys to the the aligned inputs
	memcpy(bothOutputResults, allOutputWireValues, garbledCircuitPtr->getNumberOfOutputs() * 2 * 16);
	//call the native function
	result = garbledCircuitPtr->verifyTranslationTable(bothOutputResults);
	_aligned_free(bothOutputResults);
	//now, after memory has been free return the value of the native verifyTranslationTable call.
	return result;
}

