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
	//Constructs the garbled circuit.
	values = circuit->garble();
	//Send garbled tables and the translation table to p2.
	GarbledTablesHolder * tables = circuit->getGarbledTables();
	channel->write(tables->toDoubleByteArray()[0], tables->getArraySize(0));

	channel->write(circuit->getTranslationTable(), circuit->getTranslationTableSize());
	//Send p1 input keys to p2.
	sendP1Inputs(ungarbledInput);

	//Run OT protocol in order to send p2 the necessary keys without revealing any information.
	runOTProtocol();
}

void PartyOne::runOTProtocol() {
	//Get the indices of p2 input wires.
	int p1InputSize = 0;
	int p2InputSize = 0;
	byte* allInputWireValues = values.getAllInputWireValues();
	p1InputSize = circuit->getNumberOfInputs(1);
	p2InputSize = circuit->getNumberOfInputs(2);
	vector<byte> x0Arr;
	x0Arr.reserve(p2InputSize * SIZE_OF_BLOCK);
	vector<byte> x1Arr;
	x1Arr.reserve(p2InputSize * SIZE_OF_BLOCK);
	int beginIndex0, beginIndex1;
	for (int i = 0; i<p2InputSize; i++) {
		beginIndex0 = p1InputSize * 2 * SIZE_OF_BLOCK + 2 * i*SIZE_OF_BLOCK;
		beginIndex1 = p1InputSize * 2 * SIZE_OF_BLOCK + (2 * i + 1)*SIZE_OF_BLOCK;
		x0Arr.insert(x0Arr.end(), &allInputWireValues[beginIndex0], &allInputWireValues[beginIndex0 + SIZE_OF_BLOCK]);
		x1Arr.insert(x1Arr.end(), &allInputWireValues[beginIndex1], &allInputWireValues[beginIndex1 + SIZE_OF_BLOCK]);
	}
	// create an OT input object with the keys arrays.
	OTBatchSInput * input = new OTExtensionGeneralSInput(&x0Arr[0], x0Arr.size(), &x1Arr[0], x1Arr.size(), p2InputSize);

	// run the OT's transfer phase.
	otSender->transfer(input);
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
	byte* garbledOutput = NULL;
	garbledOutput = circuit->compute();
	// translate the result from compute.
	byte* circuitOutput = circuit->translate(garbledOutput);
	return circuitOutput;
}

void PartyTwo::run(byte * ungarbledInput, int inputSize) {
	// receive tables and inputs
	cout << "party 2 starting to receive circuit and p1Inputs" << endl;
	clock_t begin0 = clock();
	receiveCircuit();
	receiveP1Inputs();
	cout << "Receive garbled tables and translation tables and p1 inpustfrom p1 took "
		<< double(clock() - begin0) / CLOCKS_PER_SEC << " secs" << endl;

	// run OT protocol in order to get the necessary keys without revealing any information.
	clock_t begin = clock();
	OTBatchROutput * output = runOTProtocol(ungarbledInput, inputSize);
	cout << "run OT took" << double(clock() - begin) / CLOCKS_PER_SEC << " secs" << endl;

	// Compute the circuit.
	begin = clock();
	byte* circuitOutput = computeCircuit(output);
	cout << "compute the circuit took" << double(clock() - begin) / CLOCKS_PER_SEC << " secs" << endl;

	// we're done print the output
	cout << "run one protocol took" << double(clock() - begin0) / CLOCKS_PER_SEC << " secs. printing output" << endl;
	int outputSize = circuit->getNumberOfParties();
	for (int i = 0; i<outputSize; i++)
		cout << circuitOutput[i];
}

void PartyTwo::receiveCircuit() {
	// receive garbled tables.
	cout << "receiving circuit" << endl;
	vector<byte> * msg;
	while ((msg = channel->read_one()) == NULL)
	{
		cout << "sleeping for 2 seconds" << endl;
		this_thread::sleep_for(chrono::seconds(2));
	}
	cout << endl << "msg is not null. size: " << msg->size() << endl;
	GarbledTablesHolder * garbledTables = new JustGarbledGarbledTablesHolder(&(msg->at(0)), msg->size());
	while ((msg = channel->read_one()) == NULL)
	{
		cout << "sleeping for 2 seconds" << endl;
		this_thread::sleep_for(chrono::seconds(2));
	}
	cout << endl << "msg is not null (again)! size: " << msg->size() << endl;
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