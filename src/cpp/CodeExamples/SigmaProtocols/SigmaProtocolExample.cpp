#include "SigmaProtocolExample.hpp"


struct SigmaDlogParams {
	biginteger w;
	biginteger p;
	biginteger q;
	biginteger g;
	int t;

	SigmaDlogParams(biginteger w, biginteger p, biginteger q, biginteger g, int t) {
		this->w = w;
		this->p = p;
		this->q = q;
		this->g = g;
		this->t = t;
	};
};

SigmaDlogParams getParams() {
	biginteger q = 3;
	biginteger p = q * 2 + 1; // p=7
	biginteger g = 2;
	int t = 1;
	return SigmaDlogParams(2, p, q, g, t);
}


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


void run_prover(ChannelServer * server) {
	int i;
	cout << "please click 0 when ready" << endl;
	cin >> i;
	connect_(server);

	SigmaDlogParams sdp = getParams();
	DlogGroup * dg = new CryptoPpDlogZpSafePrime(new ZpGroupParams(sdp.q, sdp.g, sdp.p), get_seeded_random());
	GroupElement * g = dg->getGenerator();
	GroupElement * h = dg->exponentiate(g, sdp.w);
	SigmaProverComputation* proverComputation = new SigmaDlogProverComputation(dg, sdp.t, get_seeded_random());
	SigmaProver* sp = new SigmaProver(server, proverComputation);
	auto proverinput = new SigmaDlogProverInput(h, sdp.w);
	sp->prove(proverinput);
}

void run_verifier(ChannelServer* server) {
	SigmaDlogParams sdp = getParams();
	DlogGroup * dg = new CryptoPpDlogZpSafePrime(new ZpGroupParams(sdp.q, sdp.g, sdp.p), get_seeded_random());

	connect_(server);

	GroupElement * g = dg->getGenerator();
	GroupElement * h = dg->exponentiate(g, sdp.w);
	SigmaCommonInput* commonInput = new SigmaDlogCommonInput(h);
	SigmaVerifierComputation* verifierComputation = new SigmaDlogVerifierComputation(dg, sdp.t, get_seeded_random());
	SigmaGroupElementMsg* msg1 = new SigmaGroupElementMsg(h->generateSendableData());
	SigmaBIMsg* msg2 = new SigmaBIMsg();
	SigmaVerifier* v = new SigmaVerifier(server, verifierComputation, msg1, msg2);
	v->verify(commonInput);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		SigmaProtocolExample(argv[0]);
		return 1;
	}
	string side(argv[1]);

	Logger::configure_logging();
	boost::asio::io_service io_service;
	SocketPartyData me(IpAdress::from_string("127.0.0.1"), 1212);
	SocketPartyData other(IpAdress::from_string("127.0.0.1"), 1213);
	ChannelServer * server = (side == "1")? new ChannelServer(io_service, me, other) : new ChannelServer(io_service, other, me);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	try {
		if (side == "1") {
			run_prover(server);
		}
		else if (side == "2") {
			run_verifier(server);
		}
		else {
			SigmaProtocolExample(argv[0]);
			return 1;
		}
	}
	catch (const logic_error& e) {
		// Log error message in the exception object
		cerr << e.what();
	}
	io_service.stop();
	t.join();
	return 0;
}