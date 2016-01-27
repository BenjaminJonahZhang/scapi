#include "../../include/interactive_mid_protocols/SigmaProtocol.hpp"

/***************************/
/*   SigmaProver           */
/***************************/

void SigmaProver::processFirstMsg(SigmaProverInput * input) {
	// compute the first message by the underlying proverComputation.
	SigmaProtocolMsg * a = proverComputation->computeFirstMsg(input);
	cout << "sending first message with size: " << a->size();
	//Send the first message.
	sendMsgToVerifier(a);
	cout << "first message sent" << endl;
	//save the state of this protocol.
	doneFirstMsg = true;
}

void SigmaProver::processSecondMsg() {
	if (!doneFirstMsg)
		throw IllegalStateException("processFirstMsg should be called before processSecondMsg");
	// receive the challenge.
	cout << "receiving challenge" << endl;
	auto v = channel->read_one();
	cout << "got challenge. size: " << v->size() << endl;

	// Compute the second message by the underlying proverComputation.
	SigmaProtocolMsg * z = proverComputation->computeSecondMsg(&(v->at(0)), v->size());
	cout << "seconds message computed sending to verifier" << endl;

	// send the second message.
	sendMsgToVerifier(z);
	cout << "second message sent;" << endl;

	// save the state of this sigma protocol.
	doneFirstMsg = false;
}


/***************************/
/*   SigmaVerifier         */
/***************************/
bool SigmaVerifier::verify(SigmaCommonInput * input) {
	// samples the challenge.
	cout << "sampling challenge" << endl;
	sampleChallenge();
	// sends the challenge.
	cout << "sending challenge" << endl;
	sendChallenge();
	cout << "challenge sent. starting verification" << endl;
	// serifies the proof.
	return processVerify(input);
}

void SigmaVerifier::sendChallenge() {

	// wait for first message from the prover.
	receiveMsgFromProver(a);

	// get the challenge from the verifierComputation.
	byte * challenge = verifierComputation->getChallenge();
	int challenge_size = verifierComputation->getChallengeSize();
	if (challenge_size == 0)
		throw IllegalStateException("challenge_size=0. Make sure that sampleChallenge function is called before sendChallenge");

	// send the challenge.
	sendChallengeToProver(challenge, challenge_size);

	// save the state of the protocol.
	doneChallenge = true;
}

bool SigmaVerifier::processVerify(SigmaCommonInput * input) {
	if (!doneChallenge)
		throw IllegalStateException("sampleChallenge and sendChallenge should be called before processVerify");
	// wait for second message from the prover.
	cout << "waiting for recieve" << endl;
	receiveMsgFromProver(z);
	cout << "recieved message from proveer" << endl;
	// verify the proof
	bool verified = verifierComputation->verify(input, a, z);
	cout << "tried to verify message: " << verified << endl;
	// save the state of the protocol.
	doneChallenge = false;
	return verified;
}

void SigmaVerifier::receiveMsgFromProver(SigmaProtocolMsg * msg) {
	cout << "reading a message" << endl;
	auto v = channel->read_one();
	cout << "message read. size:" << v->size() << endl;;
	msg->init_from_byte_array(&(v->at(0)), v->size());
}