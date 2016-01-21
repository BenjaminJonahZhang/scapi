#include "SigmaProtocolExample.hpp"

void SigmaProtocolExample(char * argv0) {
	std::cerr << "Usage: " << argv0 << " 1(=prover)|2(=verifier)" << std::endl;
}

void run_prover() {
	boost::asio::io_service io_service;
	SocketPartyData me(IpAdress::from_string("127.0.0.1"), 1212);
	SocketPartyData other(IpAdress::from_string("127.0.0.1"), 1213);
	ChannelServer * server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	//DlogGroup * dg = new CryptoPpDlogZpSafePrime(64);
	//SigmaProverComputation* proverComputation = new SigmaDlogProverComputation(dg, 128, get_seeded_random());
	//SigmaProver* sp = new SigmaProver(server, proverComputation);
	//sp->processFirstMsg();
}

void run_verifier() {

}

int main39(int argc, char* argv[]) {
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