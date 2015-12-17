#include <boost/thread/thread.hpp>
#include "../../ScapiCpp/include/comm/TwoPartyComm.hpp"
#define AES_KEY BC_AES_KEY
#include "../../ScapiCpp/include/circuits/FastGarbledBooleanCircuit.hpp"
#undef AES_KEY
#define AES_KEY OT_AES_KEY
#include "../../ScapiCpp/include/interactive_mid_protocols/OTSemiHonestExtension.hpp"
#undef AES_KEY
#include <ctime>

/**
* This is an implementation of party one of Yao protocol.
*/
class PartyTwo{
private:
	OTBatchReceiver * otReceiver;			//The OT object that used in the protocol.	
	FastGarbledBooleanCircuit * circuit;	//The garbled circuit used in the protocol.
	ChannelServer * channel;				//The channel between both parties.
	byte* p1Inputs;
	int p1InputsSize;
	
	/**
	* Compute the garbled circuit.
	* @param otOutput The output from the OT protocol, which are party two inputs.
	*/
	byte* computeCircuit(OTBatchROutput * otOutput) {
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

public:
	/**
	* Constructor that sets the parameters of the OT protocol and creates the garbled circuit.
	* @param channel The channel between both parties.
	* @param bc The boolean circuit that should be garbled.
	* @param mes The encryption scheme to use in the garbled circuit.
	* @param otSender The OT object to use in the protocol.
	* @param inputForTest
	*/
	PartyTwo(ChannelServer * channel, OTBatchReceiver * otReceiver, FastGarbledBooleanCircuit * circuit) {
		this->channel = channel;
		this->otReceiver = otReceiver;
		this->circuit = circuit;
	}

	/**
	* Runs the protocol.
	* @param ungarbledInput The input for the circuit, each p1's input wire gets 0 or 1.
	*/
	void run(byte * ungarbledInput, int inputSize) {
		// receive tables and inputs
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

	/**
	* Receive the circuit's garbled tables and translation table.
	*/
	void receiveCircuit() {
		// receive garbled tables.
		vector<byte> * msg= channel->read_one();
		GarbledTablesHolder * garbledTables = new JustGarbledGarbledTablesHolder(&(msg->at(0)), msg->size());
		// receive translation table.
		byte* translationTable = &(channel->read_one()->at(0));
		// set garbled tables and translation table to the circuit.
		circuit->setGarbledTables(garbledTables);
		circuit->setTranslationTable(translationTable);
	}

	/**
	* Receives party one input.
	*/
	void receiveP1Inputs() {
		auto v = channel->read_one();
		p1Inputs = &(v->at(0));
		p1InputsSize = v->size();
	}

	/**
	* Run OT protocol in order to get party two input without revealing any information.
	* @param sigmaArr Contains a byte indicates for each input wire which key to get.
	* @return The output from the OT protocol, party tw oinputs.
	*/
	OTBatchROutput * runOTProtocol(byte* sigmaArr, int arrSize) {
		//Create an OT input object with the given sigmaArr.
		OTBatchRInput * input = new OTExtensionGeneralRInput(sigmaArr, 128, arrSize);
		//Run the Ot protocol.
		return otReceiver->transfer(input);
	}
};

/**
* This application runs party two of Yao protocol.
* @param args no arguments should be passed
*/
int main(int argc, char* argv[]) {
	boost::asio::io_service io_service;
	SocketPartyData party(IpAdress::from_string("127.0.0.1"), 7667);
	SocketPartyData other(IpAdress::from_string("127.0.0.1"), 7666);
	ChannelServer * server = new ChannelServer(io_service, party, other);

	// create the garbled circuit
	auto circuit_file = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\YaoProtocol\NigelAes.txt)";
	FastGarbledBooleanCircuit * circuit = new ScNativeGarbledBooleanCircuitNoFixedKey(circuit_file, false);

	// create the OT receiver.
	clock_t begin0 = clock();
	OTBatchReceiver * otReceiver = new OTSemiHonestExtensionReceiver(party, 163, 1);
	cout << "init ot took: " << double(clock() - begin0) / CLOCKS_PER_SEC << " secs" << endl;
	


	// create Party two with the previous created objects			
	int inputSize = 250000;
	byte* ungarbledInput = new byte[inputSize];
	
	// init the P1 yao protocol and run party two of Yao protocol.
	PartyTwo * p2 = new PartyTwo(server, otReceiver, circuit);
	p2->run(ungarbledInput, inputSize);
	cout << "Yao's protocol party 2 took: " << double(clock() - begin0) / CLOCKS_PER_SEC << " secs" << endl;
}