#include "SigmaProtocolExample.hpp"



struct SigmaDlogParams {
	biginteger w;
	biginteger p;
	biginteger q;
	biginteger g;
	int t;
	IpAdress proverIp;
	IpAdress verifierIp;
	int proverPort;
	int verifierPort;

	SigmaDlogParams(biginteger w, biginteger p, biginteger q, biginteger g, int t,
		IpAdress proverIp, IpAdress verifierIp, int proverPort, int verifierPort) {
		this->w = w; // witness
		this->p = p; // group order - must be prime
		this->q = q; // sub group order - prime such that p=2q+1
		this->g = g; // generator of Zq
		this->t = t; // soundness param must be: 2^t<q
		this->proverIp = proverIp;
		this->verifierIp = verifierIp;
		this->proverPort = proverPort;
		this->verifierPort = verifierPort;
	};
};

SigmaDlogParams readSigmaConfig(string config_file) {
	ConfigFile cf(config_file);
	string input_section = cf.Value("", "input_section");
	biginteger p  = biginteger(cf.Value(input_section, "p"));
	biginteger q = biginteger(cf.Value(input_section, "q"));
	biginteger g = biginteger(cf.Value(input_section, "g"));
	biginteger w = biginteger(cf.Value(input_section, "w"));
	int t = stoi(cf.Value(input_section, "t"));
	string proverIpStr = cf.Value("", "proverIp");
	string verifierIpStr = cf.Value("", "verifierIp");
	int proverPort = stoi(cf.Value("", "proverPort"));
	int verifierPort = stoi(cf.Value("", "verifierPort"));
	auto proverIp = IpAdress::from_string(proverIpStr);
	auto verifierIp = IpAdress::from_string(verifierIpStr);
	return SigmaDlogParams(w, p, q, g, t, proverIp, verifierIp, proverPort, verifierPort);
}

void SigmaProtocolExampleUsage(char * argv0) {
	std::cerr << "Usage: " << argv0 << " <1(=prover)|2(=verifier)> config_file_path" << std::endl;
}

void run_prover(ChannelServer * server, SigmaDlogParams sdp) {
	DlogGroup * dg = new CryptoPpDlogZpSafePrime(new ZpGroupParams(sdp.q, sdp.g, sdp.p), 
		get_seeded_random());

	server->try_connecting(500, 5000); // sleep time=500, timeout = 5000 (ms);
	GroupElement * g = dg->getGenerator();
	GroupElement * h = dg->exponentiate(g, sdp.w);
	SigmaProverComputation* proverComputation = new SigmaDlogProverComputation(dg, sdp.t, 
		get_seeded_random());
	SigmaProver* sp = new SigmaProver(server, proverComputation);
	auto proverinput = new SigmaDlogProverInput(h, sdp.w);
	sp->prove(proverinput);
}

void run_verifier(ChannelServer* server, SigmaDlogParams sdp) {
	DlogGroup * dg = new CryptoPpDlogZpSafePrime(new ZpGroupParams(sdp.q, sdp.g, sdp.p), 
		get_seeded_random());

	server->try_connecting(500, 5000); // sleep time=500, timeout = 5000 (ms);
	GroupElement * g = dg->getGenerator();
	GroupElement * h = dg->exponentiate(g, sdp.w);
	SigmaCommonInput* commonInput = new SigmaDlogCommonInput(h);
	SigmaVerifierComputation* verifierComputation = new SigmaDlogVerifierComputation(dg, sdp.t,
		get_seeded_random());
	SigmaGroupElementMsg* msg1 = new SigmaGroupElementMsg(h->generateSendableData());
	SigmaBIMsg* msg2 = new SigmaBIMsg();
	SigmaVerifier* v = new SigmaVerifier(server, verifierComputation, msg1, msg2);
	bool verificationPassed = v->verify(commonInput);
	cout << "Verifer output: " << (verificationPassed? "Success" : "Failure") << endl;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		SigmaProtocolExampleUsage(argv[0]);
		return 1;
	}
	SigmaDlogParams sdp = readSigmaConfig(argv[2]);
	string side(argv[1]);

	Logger::configure_logging();
	boost::asio::io_service io_service;
	SocketPartyData proverParty(sdp.proverIp, sdp.proverPort);
	SocketPartyData verifierParty(sdp.verifierIp, sdp.verifierPort);
	ChannelServer * server = (side == "1")? 
		new ChannelServer(io_service, proverParty, verifierParty) : 
		new ChannelServer(io_service, verifierParty, proverParty);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	try {
		if (side == "1") {
			run_prover(server, sdp);
		}
		else if (side == "2") {
			run_verifier(server, sdp);
		}
		else {
			SigmaProtocolExampleUsage(argv[0]);
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