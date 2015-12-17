#include "YaoExample.hpp"
auto circuit_file = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\YaoProtocol\NigelAes.txt)";
auto localhost_ip = IpAdress::from_string("127.0.0.1");

void execute_party_one() {
	clock_t begin0 = clock();
	boost::asio::io_service io_service;
	SocketPartyData me(localhost_ip, 1213);
	SocketPartyData other(localhost_ip, 1212);
	ChannelServer * channel_server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	cout << "init ot took: " << double(clock() - begin0) / CLOCKS_PER_SEC << " secs" << endl;
	
	// create the garbled circuit
	clock_t begin = clock();
	FastGarbledBooleanCircuit * circuit = new ScNativeGarbledBooleanCircuitNoFixedKey(circuit_file, false);
	cout << "Creating circuit: " << double(clock() - begin) / CLOCKS_PER_SEC << 
		" secs. Circuits size " << circuit->getTranslationTableSize() <<  endl << "creating OTSender now..." << endl;
	
	begin = clock();
	SocketPartyData senderParty(localhost_ip, 7766);
	OTBatchSender * otSender = new OTSemiHonestExtensionSender(senderParty, 163, 1);
	cout << "Created Sender. took: " << double(clock() - begin) / CLOCKS_PER_SEC << " secs" << endl;
	cout << "Connecting to receiver now" << endl;
	int i;
	cout << "please click 0 when ready" << endl;
	cin >> i;
	channel_server->connect();
	this_thread::sleep_for(chrono::seconds(3));
	if (!channel_server->is_connected())
	{
		cout << "sorry. connection failed" << endl;
		return;
	}
	else
		cout << "connected. starting to send" << endl;

	// get the inputs of P1.
	byte* ungarbledInput = new byte[250000];
	// create Party one with the previous created objects.
	PartyOne * p1 = new PartyOne(channel_server, otSender, circuit);
	p1->run(ungarbledInput);
}

void execute_party_two() {
	clock_t begin0 = clock();
	boost::asio::io_service io_service;
	SocketPartyData me(localhost_ip, 1212);
	SocketPartyData other(localhost_ip, 1213);
	ChannelServer * server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	cout << "init ot took: " << double(clock() - begin0) / CLOCKS_PER_SEC << " secs" << endl;


	// create the garbled circuit
	cout << "creating garbled circuit using file at: " << circuit_file << endl;
	clock_t begin = clock();
	FastGarbledBooleanCircuit * circuit = new ScNativeGarbledBooleanCircuitNoFixedKey(circuit_file, false);
	cout << "Creating circuit too: " << double(clock() - begin) / CLOCKS_PER_SEC <<
		" secs. Circuits size " << circuit->getTranslationTableSize() << endl;
	

	// create the OT receiver.
	cout << "creating OTReceiver now..." << endl;
	begin = clock();
	SocketPartyData receiverParty(localhost_ip, 7766);
	OTBatchReceiver * otReceiver = new OTSemiHonestExtensionReceiver(receiverParty, 163, 1);
	cout << "Creating OTBatchReceiver took: " << double(clock() - begin) / CLOCKS_PER_SEC << " secs" << endl;

	// create Party two with the previous created objects			
	int inputSize = 250000;
	byte* ungarbledInput = new byte[inputSize];

	// init the P1 yao protocol and run party two of Yao protocol.
	cout << "creating PartyTwo now..." << endl;
	begin = clock();
	PartyTwo * p2 = new PartyTwo(server, otReceiver, circuit);
	cout << "Creating PartyTwo took: " << double(clock() - begin) / CLOCKS_PER_SEC << " secs" << endl;
	cout << "starting to run party tow..." << endl;
	begin = clock();
	p2->run(ungarbledInput, inputSize);
	cout << "Run took: " << double(clock() - begin) / CLOCKS_PER_SEC << " secs" << endl;
	cout << "Yao's protocol party 2 took: " << double(clock() - begin0) / CLOCKS_PER_SEC << " secs" << endl;
}

void Usage(char * argv0) {
	std::cerr << "Usage: " << argv0 << " 1 (for party one) or 2 (for party two)" << std::endl;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		Usage(argv[0]);
		return 1;
	}
	string partyNum(argv[1]);
	if (partyNum == "1")
		execute_party_one();
	else if (partyNum == "2")
		execute_party_two();
	else {
		Usage(argv[0]);
		return 1;
	}
	return 0;
}