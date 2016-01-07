#include "YaoExample.hpp"


// Config:
int number_of_iterations = 1000;
bool print_output = false;
#ifdef __linux__ 
auto circuit_file = R"(../../../java/edu/biu/SCProtocols/YaoProtocol/NigelAes.txt)";
#else
//auto circuit_file = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\YaoProtocol\NigelAes.txt)";
//auto circuit_file = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\AES\NigelAes.txt)";
//auto circuit_file = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\SHA1\NigelSHA1.txt)";
auto circuit_file = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\SHA256\NigelSHA256.txt)";
#endif
auto party_1_ip = IpAdress::from_string("127.0.0.1");
auto party_2_ip = IpAdress::from_string("127.0.0.1");
//input_file_2 = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\AES\AESPartyOneInputs.txt)";
//auto input_file_1 = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\SHA1\SHA1PartyOneInputs.txt)";
auto input_file_1 = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\SHA256\SHA256PartyOneInputs.txt)";
//input_file_2 = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\AES\AESPartyTwoInputs.txt)";
//auto input_file_2 = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\SHA1\SHA1PartyTwoInputs.txt)";
auto input_file_2 = R"(C:\code\scapi\src\java\edu\biu\SCProtocols\MaliciousYao\assets\circuits\SHA256\SHA256PartyTwoInputs.txt)";

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

vector<byte> * readInputAsVector(int party) {
	string input_file = (party == 1) ? input_file_1 : input_file_2;
	cout << "reading from file " << input_file << endl;;
	auto sc = scannerpp::Scanner(new scannerpp::File(input_file));
	int inputsNumber = sc.nextInt();
	auto inputVector = new vector<byte>(inputsNumber);
	for (int i = 0; i < inputsNumber; i++)
		(*inputVector)[i] = (byte)sc.nextInt();
	return inputVector;
}

void execute_party_one() {
	auto start = chrono::system_clock::now();
	boost::asio::io_service io_service;
	SocketPartyData me(party_1_ip, 1213);
	SocketPartyData other(party_2_ip, 1212);
	ChannelServer * channel_server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	print_elapsed_ms(start, "PartyOne: Init");
	
	// create the garbled circuit
	start = chrono::system_clock::now();
	FastGarbledBooleanCircuit * circuit = new ScNativeGarbledBooleanCircuitNoFixedKey(circuit_file, true);
	print_elapsed_ms(start, "PartyOne: Creating FastGarbledBooleanCircuit");
	
	// create the semi honest OT extension sender
	SocketPartyData senderParty(party_2_ip, 7766);
	OTBatchSender * otSender = new OTSemiHonestExtensionSender(senderParty, 163, 1);

	// connect to party two
	connect(channel_server);
	
	// get the inputs of P1 
	vector<byte>* ungarbledInput = readInputAsVector(1);

	PartyOne * p1;
	auto all = scapi_now();
	// create Party one with the previous created objects.
	p1 = new PartyOne(channel_server, otSender, circuit);
	for (int i = 0; i < number_of_iterations ; i++) {
		// run Party one
		p1->run(&(ungarbledInput->at(0)));
	}
	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
	cout << "********************* PartyOne: Running " << number_of_iterations <<
		" iterations too: " << elapsed_ms << " milliseconds" << endl;
	cout << "Average time per iteration: " << elapsed_ms / (float) number_of_iterations << " milliseconds" << endl;
	
	// exit cleanly
	delete p1, channel_server, circuit, otSender, ungarbledInput;
	io_service.stop();
	t.join();
}

void execute_party_two() {
	// init
	auto start = scapi_now();
	boost::asio::io_service io_service;
	SocketPartyData me(party_2_ip, 1212);
	SocketPartyData other(party_1_ip, 1213);
	SocketPartyData receiverParty(party_1_ip, 7766);
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
	vector<byte> * ungarbledInput = readInputAsVector(2);

	PartyTwo * p2;
	auto all = scapi_now();
	p2 = new PartyTwo(server, otReceiver, circuit);
	for (int i = 0; i < number_of_iterations ; i++) {
		// init the P1 yao protocol and run party two of Yao protocol.
		p2->run(&(ungarbledInput->at(0)), ungarbledInput->size(), print_output);
	}
	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
	cout << "********************* PartyTwo: Running " << number_of_iterations <<
		" iterations too: " << elapsed_ms << " milliseconds" << endl;
	cout << "Average time per iteration: " << elapsed_ms / (float) number_of_iterations << " milliseconds" << endl;
	delete p2, server, circuit, otReceiver, ungarbledInput;
	io_service.stop();
	t.join();
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

