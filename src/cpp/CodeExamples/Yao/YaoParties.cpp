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
	auto start = scapi_now();
	for (int i = 0; i < 1000; i++) {
		values = circuit->garble();
	}
	print_elapsed_ms(start, "Garbling");
	// send garbled tables and the translation table to p2.
	start = scapi_now();
	GarbledTablesHolder * tables = circuit->getGarbledTables();
	channel->write(tables->toDoubleByteArray()[0], tables->getArraySize(0));
	channel->write(circuit->getTranslationTable(), circuit->getTranslationTableSize());
	// send p1 input keys to p2.
	sendP1Inputs(ungarbledInput);
	print_elapsed_ms(start, "Sent garbled tables, translation table and p1Input to p2");

	// run OT protocol in order to send p2 the necessary keys without revealing any information.
	start = chrono::system_clock::now();
	runOTProtocol();
	print_elapsed_ms(start, "PartyOne: OT protocol run");
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
	print_elapsed_ms(start, "PartyOne: transfer part of OT");
}

/*********************************/
/*          PartyTwo             */
/*********************************/

byte* PartyTwo::computeCircuit(OTBatchROutput * otOutput) {
	auto start = scapi_now();
	// Get the output of the protocol.
	byte* p2Inputs = ((OTOnByteArrayROutput *)otOutput)->getXSigma();
	int p2InputsSize = ((OTOnByteArrayROutput *)otOutput)->getLength();
	// Get party two input wires' indices.
	int* labels = NULL;
	labels = circuit->getInputWireIndices(2);
	vector<byte> allInputs(p1InputsSize + p2InputsSize);
	memcpy(&allInputs[0], p1Inputs, p1InputsSize);
	memcpy(&allInputs[p1InputsSize], p2Inputs, p2InputsSize);
	print_elapsed_ms(start, "PartyTow: ComputeCircuit: init");
	
	// set the input to the circuit.
	start = scapi_now();
	circuit->setInputs(allInputs);
	print_elapsed_ms(start, "PartyTow: ComputeCircuit: setInputs");
	
	// compute the circuit.
	byte* garbledOutput;
	start = scapi_now();
	for (int i = 0; i < 1000; i++) {
		garbledOutput = NULL;
		garbledOutput = circuit->compute();
	}
	print_elapsed_ms(start, "PartyTow: ComputeCircuit: compute");
	
	// translate the result from compute.
	start = scapi_now();
	byte* circuitOutput = circuit->translate(garbledOutput);
	print_elapsed_ms(start, "PartyTow: ComputeCircuit: translate");
	return circuitOutput;
}

void PartyTwo::run(byte * ungarbledInput, int inputSize) {
	// receive tables and inputs
	auto start = scapi_now();
	receiveCircuit();
	receiveP1Inputs();
	print_elapsed_ms(start, "PartyTwo: receive garbled tables,translation table and p1 inpust from p1");

	// run OT protocol in order to get the necessary keys without revealing any information.
	start = scapi_now();
	OTBatchROutput * output = runOTProtocol(ungarbledInput, inputSize);
	print_elapsed_ms(start, "PartyTwo: run OT protocol");

	// Compute the circuit.
	start = scapi_now();
	byte* circuitOutput = computeCircuit(output);
	print_elapsed_ms(start, "PartyTwo: Compute the circuit took");

	// we're done print the output
	int outputSize = circuit->getNumberOfParties();
	cout << "PartyTwo: printing outputSize: " << outputSize << endl;
	for (int i = 0; i<outputSize; i++)
		cout << circuitOutput[i];
}

void PartyTwo::receiveCircuit() {
	// receive garbled tables.
	vector<byte> * msg;
	int sleep_seconds = 3;
	while ((msg = channel->read_one()) == NULL)
	{
		cout << "sleeping for: " << sleep_seconds << " seconds" << endl;
		this_thread::sleep_for(chrono::seconds(sleep_seconds));
	}
	GarbledTablesHolder * garbledTables = new JustGarbledGarbledTablesHolder(&(msg->at(0)), msg->size());
	while ((msg = channel->read_one()) == NULL)
	{
		cout << "sleeping for: " << sleep_seconds << " seconds" << endl;
		this_thread::sleep_for(chrono::seconds(sleep_seconds-1));
	}
	// receive translation table.
	byte* translationTable = &(msg->at(0));
	// set garbled tables and translation table to the circuit.
	circuit->setGarbledTables(garbledTables);
	circuit->setTranslationTable(translationTable);
}

void PartyTwo::receiveP1Inputs() {
	vector<byte> * msg;
	while ((msg = channel->read_one()) == NULL)
	{
		cout << "sleeping for 2 seconds" << endl;
		this_thread::sleep_for(chrono::seconds(2));
	}
	cout << endl << "msg is not null (again)! size: " << msg->size() << endl;
	p1Inputs = &(msg->at(0));
	p1InputsSize = msg->size();
};