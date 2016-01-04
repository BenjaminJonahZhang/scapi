#include "YaoExample.hpp"
/*********************************/
/*          PartyOne             */
/*********************************/
void PartyOne::sendP1Inputs(byte* ungarbledInput) {
	byte* allInputs = values.getAllInputWireValues();
	//get the size of party one inputs
	int numberOfp1Inputs = 0;
	numberOfp1Inputs = circuit->getNumberOfInputs(1);
	int inputsSize = numberOfp1Inputs*SIZE_OF_BLOCK;
	byte* p1Inputs = new byte[inputsSize];
	//Create an array with the keys corresponding the given input.
	int inputStartIndex;
	for (int i = 0; i < numberOfp1Inputs; i++) {
		inputStartIndex = (2 * i + ungarbledInput[i])*SIZE_OF_BLOCK;
		memcpy(p1Inputs + i*SIZE_OF_BLOCK, allInputs + inputStartIndex, SIZE_OF_BLOCK);
	}
	//Send the keys to p2.
	channel->write(p1Inputs, inputsSize);
}

void PartyOne::run(byte * ungarbledInput) {
	values = circuit->garble();
	// send garbled tables and the translation table to p2.
	GarbledTablesHolder * tables = circuit->getGarbledTables();
	channel->write(tables->toDoubleByteArray()[0], tables->getArraySize(0));
	channel->write(circuit->getTranslationTable(), circuit->getTranslationTableSize());
	// send p1 input keys to p2.
	sendP1Inputs(ungarbledInput);

	// run OT protocol in order to send p2 the necessary keys without revealing any information.
	runOTProtocol();
}

void PartyOne::runOTProtocol() {
	//Get the indices of p2 input wires.
	int p1InputSize = 0;
	int p2InputSize = 0;
	byte* allInputWireValues = values.getAllInputWireValues();
	p1InputSize = circuit->getNumberOfInputs(1);
	p2InputSize = circuit->getNumberOfInputs(2);
	auto x0Arr = new vector<byte>();
	x0Arr->reserve(p2InputSize * SIZE_OF_BLOCK);
	auto x1Arr = new vector<byte>();
	x1Arr->reserve(p2InputSize * SIZE_OF_BLOCK);
	int beginIndex0, beginIndex1;
	for (int i = 0; i<p2InputSize; i++) {
		beginIndex0 = p1InputSize * 2 * SIZE_OF_BLOCK + 2 * i*SIZE_OF_BLOCK;
		beginIndex1 = p1InputSize * 2 * SIZE_OF_BLOCK + (2 * i + 1)*SIZE_OF_BLOCK;
		x0Arr->insert(x0Arr->end(), &allInputWireValues[beginIndex0], &allInputWireValues[beginIndex0 + SIZE_OF_BLOCK]);
		x1Arr->insert(x1Arr->end(), &allInputWireValues[beginIndex1], &allInputWireValues[beginIndex1 + SIZE_OF_BLOCK]);
	}
	// create an OT input object with the keys arrays.
	OTBatchSInput * input = new OTExtensionGeneralSInput(&(x0Arr->at(0)), x0Arr->size(), &(x1Arr->at(0)), x1Arr->size(), p2InputSize);
	// run the OT's transfer phase.
	auto start = chrono::system_clock::now();
	otSender->transfer(input);
	//print_elapsed_ms(start, "PartyOne: transfer part of OT");
}

/*********************************/
/*          PartyTwo             */
/*********************************/

byte* PartyTwo::computeCircuit(OTBatchROutput * otOutput) {
	// Get the output of the protocol.
	byte* p2Inputs = ((OTOnByteArrayROutput *)otOutput)->getXSigma();
	int p2InputsSize = ((OTOnByteArrayROutput *)otOutput)->getLength();
	// Get party two input wires' indices.
	int* labels = NULL;
	labels = circuit->getInputWireIndices(2);
	vector<byte> allInputs(p1InputsSize + p2InputsSize);
	memcpy(&allInputs[0], p1Inputs, p1InputsSize);
	memcpy(&allInputs[p1InputsSize], p2Inputs, p2InputsSize);
	
	// set the input to the circuit.
	circuit->setInputs(allInputs);
	
	// compute the circuit.
	byte* garbledOutput;
	garbledOutput = circuit->compute();
	
	// translate the result from compute.
	byte* circuitOutput = circuit->translate(garbledOutput);
	return circuitOutput;
}

void PartyTwo::run(byte * ungarbledInput, int inputSize) {
	// receive tables and inputs
	receiveCircuit();
	receiveP1Inputs();

	// run OT protocol in order to get the necessary keys without revealing any information.
	OTBatchROutput * output = runOTProtocol(ungarbledInput, inputSize);

	// Compute the circuit.
	byte* circuitOutput = computeCircuit(output);

	//// we're done print the output
	//int outputSize = circuit->getNumberOfParties();
	//cout << "PartyTwo: printing outputSize: " << outputSize << endl;
	//for (int i = 0; i<outputSize; i++)
	//	cout << circuitOutput[i];
}

void PartyTwo::receiveCircuit() {
	// receive garbled tables.
	auto msg = channel->read_one();
	GarbledTablesHolder * garbledTables = new JustGarbledGarbledTablesHolder(&(msg->at(0)), msg->size());
	msg = channel->read_one();
	// receive translation table.
	byte* translationTable = &(msg->at(0));
	// set garbled tables and translation table to the circuit.
	circuit->setGarbledTables(garbledTables);
	circuit->setTranslationTable(translationTable);
}

void PartyTwo::receiveP1Inputs() {
	auto msg = channel->read_one();
	p1Inputs = &(msg->at(0));
	p1InputsSize = msg->size();
};