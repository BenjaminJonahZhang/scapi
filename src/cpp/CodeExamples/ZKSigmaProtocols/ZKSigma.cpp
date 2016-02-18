#include <boost/thread/thread.hpp>
#include "../../ScapiCpp/include/comm/TwoPartyComm.hpp"
#include "../../ScapiCpp/include/interactive_mid_protocols/SigmaProtocolDlog.hpp"
#include "../../ScapiCpp/include/interactive_mid_protocols/ZeroKnowledge.hpp"
#include "../../ScapiCpp/include/primitives/DlogOpenSSL.hpp"
#include "../../ScapiCpp/include/infra/Scanner.hpp"
#include "../../ScapiCpp/include/infra/ConfigFile.hpp"

struct ZKSigmaDlogParams {
	biginteger w;
	biginteger p;
	biginteger q;
	biginteger g;
	int t;
	IpAdress proverIp;
	IpAdress verifierIp;
	int proverPort;
	int verifierPort;

	ZKSigmaDlogParams(biginteger w, biginteger p, biginteger q, biginteger g, int t,
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

ZKSigmaDlogParams readZKSigmaConfig(string config_file) {
	ConfigFile cf(config_file);
	string input_section = cf.Value("", "input_section");
	biginteger p = biginteger(cf.Value(input_section, "p"));
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
	return ZKSigmaDlogParams(w, p, q, g, t, proverIp, verifierIp, proverPort, verifierPort);
}

void ZKSigmaUsage(char * argv0) {
	std::cerr << "Usage: " << argv0 << " <1(=prover)|2(=verifier)> config_file_path" << std::endl;
}

void run_prover_zk(std::shared_ptr<ChannelServer> server, ZKSigmaDlogParams sdp) {
	auto zp_params = make_shared<ZpGroupParams>(sdp.q, sdp.g, sdp.p);
	auto dg = make_shared<OpenSSLDlogZpSafePrime>(zp_params);
	server->try_connecting(500, 5000); // sleep time=500, timeout = 5000 (ms);
	std::shared_ptr<GroupElement> g = dg->getGenerator();
	std::shared_ptr<GroupElement> h = dg->exponentiate(g, sdp.w);
	auto proverComputation = make_shared<SigmaDlogProverComputation>(dg, sdp.t,
		get_seeded_random());
	auto sp = new ZKPOKFromSigmaCmtPedersenProver(server, proverComputation);
	auto proverinput = make_shared<SigmaDlogProverInput>(h, sdp.w);
	sp->prove(proverinput);
}

void run_verifier_zk(shared_ptr<ChannelServer> server, ZKSigmaDlogParams sdp) {
	auto zp_params = make_shared<ZpGroupParams>(sdp.q, sdp.g, sdp.p);
	auto openSSLdg = make_shared<OpenSSLDlogZpSafePrime>(zp_params, get_seeded_random());
	auto dg = std::static_pointer_cast<DlogGroup>(openSSLdg);

	server->try_connecting(500, 5000); // sleep time=500, timeout = 5000 (ms);
	auto g = dg->getGenerator();
	auto h = dg->exponentiate(g, sdp.w);
	auto commonInput = make_shared<SigmaDlogCommonInput>(h);
	auto verifierComputation = make_shared<SigmaDlogVerifierComputation>(
		dg, sdp.t, get_seeded_random());
	auto msg1 = make_shared<SigmaGroupElementMsg>(h->generateSendableData());
	auto msg2 = make_shared<SigmaGroupElementMsg>(h->generateSendableData());
	auto emptyTrap = make_shared<CmtRBasicCommitPhaseOutput>(0);
	auto v = new ZKPOKFromSigmaCmtPedersenVerifier(server, verifierComputation, 
		get_seeded_random64(), emptyTrap);
	bool verificationPassed = v->verify(commonInput, msg1, msg2);
	cout << "Verifer output: " << (verificationPassed ? "Success" : "Failure") << endl;
	delete v;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		ZKSigmaUsage(argv[0]);
		return 1;
	}
	ZKSigmaDlogParams sdp = readZKSigmaConfig(argv[2]);
	string side(argv[1]);

	Logger::configure_logging();
	boost::asio::io_service io_service;
	SocketPartyData proverParty(sdp.proverIp, sdp.proverPort);
	SocketPartyData verifierParty(sdp.verifierIp, sdp.verifierPort);
	shared_ptr<ChannelServer> server = (side == "1") ?
		make_shared<ChannelServer>(io_service, proverParty, verifierParty) :
		make_shared<ChannelServer>(io_service, verifierParty, proverParty);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	try {
		if (side == "1") {
			run_prover_zk(server, sdp);
		}
		else if (side == "2") {
			run_verifier_zk(server, sdp);
		}
		else {
			ZKSigmaUsage(argv[0]);
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