#include <boost/thread/thread.hpp>
#include "../../ScapiCpp/include/comm/TwoPartyComm.hpp"
#define AES_KEY BC_AES_KEY
#include "../../ScapiCpp/include/circuits/FastGarbledBooleanCircuit.hpp"
#undef AES_KEY
#define AES_KEY OT_AES_KEY
#include "../../ScapiCpp/include/interactive_mid_protocols/OTSemiHonestExtension.hpp"
#undef AES_KEY

/**
* This is an implementation of party one of Yao protocol.
*/
class PartyOne {
private:
	OTBatchSender * otSender;			//The OT object that used in the protocol.	
	FastGarbledBooleanCircuit * circuit;	//The garbled circuit used in the protocol.
	ChannelServer * channel;				//The channel between both parties.
	FastCircuitCreationValues values;
	
	/**
	* Sends p1 input keys to p2.
	* @param ungarbledInput The boolean input of each wire.
	* @param bs The keys for each wire.
	* @throws IOException In case there was a problem to send via the channel.
	*/
	void sendP1Inputs(byte* ungarbledInput) {
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
public:
	/**
	* Constructor that sets the parameters of the OT protocol and creates the garbled circuit.
	* @param channel The channel between both parties.
	* @param bc The boolean circuit that should be garbled.
	* @param mes The encryption scheme to use in the garbled circuit.
	* @param otSender The OT object to use in the protocol.
	* @param inputForTest
	*/
	PartyOne(ChannelServer * channel, OTBatchSender * otSender, FastGarbledBooleanCircuit * circuit) {
		this->channel = channel;
		this->otSender = otSender;
		this->circuit = circuit;
	}

	/**
	* Runs the protocol.
	* @param ungarbledInput The input for the circuit, each p1's input wire gets 0 or 1.
	* @throws IOException
	* @throws ClassNotFoundException
	* @throws CheatAttemptException
	* @throws InvalidDlogGroupException
	* @throws NotAllInputsSetException
	*/
	void run(byte * ungarbledInput){
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

	/**
	* Runs OT protocol in order to send p2 the necessary keys without revealing any other information.
	* @param allInputWireValues The keys for each wire.
	* @throws ClassNotFoundException
	* @throws IOException
	* @throws CheatAttemptException
	* @throws InvalidDlogGroupException
	*/
	void runOTProtocol(){
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
};

/**
* @param args no arguments should be passed
*/
int main2(int argc, char* argv[]) {
	boost::asio::io_service io_service;
	SocketPartyData party(IpAdress::from_string("127.0.0.1"), 7666);
	SocketPartyData other(IpAdress::from_string("127.0.0.1"), 7667);
	ChannelServer * server = new ChannelServer(io_service, party, other);

	FastGarbledBooleanCircuit * circuit = new ScNativeGarbledBooleanCircuitNoFixedKey("NigelMinCircuit.txt", false);
	OTBatchSender * otSender = new OTSemiHonestExtensionSender(party, 163, 1);


	int i;
	cout << "please click 0 when ready" << endl;
	cin >> i;
	server->connect();
	if (!server->is_connected())
	{
		cout << "sorry. connection failed" << endl;
		return -1;
	}
	else
		cout << "connected. starting to send" << endl;



	//Get the inputs of P1.
	byte* ungarbledInput = new byte[250000];
	//Create Party one with the previous created objects.
	PartyOne * p1 = new PartyOne(server, otSender, circuit);
	p1->run(ungarbledInput);
}
