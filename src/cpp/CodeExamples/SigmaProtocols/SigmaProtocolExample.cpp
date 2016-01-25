#include "SigmaProtocolExample.hpp"

void SigmaProtocolExample(char * argv0) {
	std::cerr << "Usage: " << argv0 << " 1(=prover)|2(=verifier)" << std::endl;
}


void connect_(ChannelServer * channel_server) {
	cout << "PartyOne: Connecting to Receiver..." << endl;
	int sleep_time = 50;
	this_thread::sleep_for(chrono::milliseconds(sleep_time));
	channel_server->connect();
	while (!channel_server->is_connected())
	{
		cout << "Failed to connect. sleeping for " << sleep_time << " milliseconds" << endl;
		this_thread::sleep_for(chrono::milliseconds(sleep_time));
	}
	cout << "Sender Connected!" << endl;
}


void run_prover() {
	boost::asio::io_service io_service;
	SocketPartyData me(IpAdress::from_string("127.0.0.1"), 1212);
	SocketPartyData other(IpAdress::from_string("127.0.0.1"), 1213);
	ChannelServer * server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

	connect_(server);

	DlogGroup * dg = new CryptoPpDlogZpSafePrime(64);
	GroupElement * g = dg->getGenerator();
	biginteger w = 100;
	GroupElement * h = dg->exponentiate(g, w);
	SigmaProverComputation* proverComputation = new SigmaDlogProverComputation(dg, 16, get_seeded_random());
	SigmaProver* sp = new SigmaProver(server, proverComputation);
	auto proverinput = new SigmaDlogProverInput(h, w);
	sp->prove(proverinput);
}

void run_verifier() {
	boost::asio::io_service io_service;
	SocketPartyData me(IpAdress::from_string("127.0.0.1"), 1213);
	SocketPartyData other(IpAdress::from_string("127.0.0.1"), 1212);
	ChannelServer * server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	DlogGroup * dg = new CryptoPpDlogZpSafePrime(64);

	//connect_(server);

	GroupElement * g = dg->getGenerator();
	biginteger w = 100;
	GroupElement * h = dg->exponentiate(g, w);
	SigmaCommonInput* commonInput = new SigmaDlogCommonInput(h);
	SigmaVerifierComputation* verifierComputation = new SigmaDlogVerifierComputation(dg, 16, get_seeded_random());
	SigmaGroupElementMsg* msg1 = new SigmaGroupElementMsg(h->generateSendableData());
	SigmaBIMsg* msg2 = new SigmaBIMsg();
	SigmaVerifier* v = new SigmaVerifier(server, verifierComputation, msg1, msg2);
	v->verify(commonInput);
}

int main(int argc, char* argv[]) {
	Logger::configure_logging();
	if (argc != 2) {
		SigmaProtocolExample(argv[0]);
		return 1;
	}
	string side(argv[1]);
	if (side == "1")
		run_prover();
	else if (side == "2")
		run_verifier();
	else {
		SigmaProtocolExample(argv[0]);
		return 1;
	}
	return 0;
}