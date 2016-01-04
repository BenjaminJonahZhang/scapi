#include "YaoExample.hpp"

int number_of_iterations = 1000;
#ifdef __linux__ 
auto circuit_file = R"(../../../java/edu/biu/SCProtocols/YaoProtocol/NigelAes.txt)";
#else
auto circuit_file = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\YaoProtocol\NigelAes.txt)";
#endif
auto localhost_ip = IpAdress::from_string("127.0.0.1");

void connect(ChannelServer * channel_server) {
	cout << "PartyOne: Connecting to Receiver..." << endl;
	int sleep_time = 50;
	this_thread::sleep_for(chrono::milliseconds(sleep_time));
	channel_server->connect();
	while(!channel_server->is_connected())
	{
		cout << "Failed to connect. sleeping for " << sleep_time << " milliseconds" << endl;
		this_thread::sleep_for(chrono::milliseconds(sleep_time));
	}
	cout << "Sender Connected!" << endl;
}

byte * readInputsAsArray() {
	return new byte[128];
}

void execute_party_one() {
	auto start = chrono::system_clock::now();
	boost::asio::io_service io_service;
	SocketPartyData me(localhost_ip, 1213);
	SocketPartyData other(localhost_ip, 1212);
	ChannelServer * channel_server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	print_elapsed_ms(start, "PartyOne: Init");
	
	// create the garbled circuit
	start = chrono::system_clock::now();
	FastGarbledBooleanCircuit * circuit = new ScNativeGarbledBooleanCircuitNoFixedKey(circuit_file, true);
	print_elapsed_ms(start, "PartyOne: Creating FastGarbledBooleanCircuit");
	
	// create the semi honest OT extension sender
	SocketPartyData senderParty(localhost_ip, 7766);
	OTBatchSender * otSender = new OTSemiHonestExtensionSender(senderParty, 163, 1);

	// connect to party two
	connect(channel_server);
	
	// get the inputs of P1 
	byte* ungarbledInput = readInputsAsArray();
	
	PartyOne * p1;
	auto all = scapi_now();
	for (int i = 0; i < number_of_iterations ; i++) {
		// create Party one with the previous created objects.
		p1 = new PartyOne(channel_server, otSender, circuit);
		// run Party one
		if (i==0)
			all = scapi_now();
		p1->run(ungarbledInput);
	}
	print_elapsed_ms(all, "********************* PartyOne: 900 iterations ALL");
	delete p1;
}

void execute_party_two() {
	// init
	auto start = scapi_now();
	boost::asio::io_service io_service;
	SocketPartyData me(localhost_ip, 1212);
	SocketPartyData other(localhost_ip, 1213);
	SocketPartyData receiverParty(localhost_ip, 7766);
	ChannelServer * server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	print_elapsed_ms(start, "PartyTwo: Init");

	// create the garbled circuit
	start = scapi_now();
	FastGarbledBooleanCircuit * circuit = new ScNativeGarbledBooleanCircuitNoFixedKey(circuit_file, true);
	print_elapsed_ms(start, "PartyTwo: creating FastGarbledBooleanCircuit");

	// create the OT receiver.
	start = scapi_now();
	OTBatchReceiver * otReceiver = new OTSemiHonestExtensionReceiver(receiverParty, 163, 1);
	print_elapsed_ms(start, "PartyTwo: creating OTSemiHonestExtensionReceiver");

	// create Party two with the previous created objec ts			
	int inputSize = 128;
	byte* ungarbledInput = new byte[inputSize];

	PartyTwo * p2;
	auto all = scapi_now();
	for (int i = 0; i < number_of_iterations ; i++) {
		// init the P1 yao protocol and run party two of Yao protocol.
		if (i == 0)
			all = scapi_now();
		p2 = new PartyTwo(server, otReceiver, circuit);
		p2->run(ungarbledInput, inputSize);
	}
	print_elapsed_ms(all, "********************* PartyTwo: 900 iterations ALL");
	delete p2;
}

void Usage(char * argv0) {
	std::cerr << "Usage: " << argv0 << " 1 (for party one) or 2 (for party two)" << std::endl;
}

int main(int argc, char* argv[]) {
	Logger::configure_logging();
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

