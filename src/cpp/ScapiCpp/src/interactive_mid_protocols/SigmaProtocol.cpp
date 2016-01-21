#include "../../include/interactive_mid_protocols/SigmaProtocol.hpp"

/***************************/
/*   SigmaProver           */
/***************************/

void SigmaProver::processFirstMsg(SigmaProverInput * input) {
	// compute the first message by the underlying proverComputation.
	SigmaProtocolMsg * a = proverComputation->computeFirstMsg(input);
	//Send the first message.
	sendMsgToVerifier(a);
	//save the state of this protocol.
	doneFirstMsg = true;
}

void SigmaProver::processSecondMsg() {
	if (!doneFirstMsg)
		throw IllegalStateException("processFirstMsg should be called before processSecondMsg");
	// receive the challenge.
	auto v = channel->read_one();

	// Compute the second message by the underlying proverComputation.
	SigmaProtocolMsg * z = proverComputation->computeSecondMsg(&(v->at(0)), v->size());

	// send the second message.
	sendMsgToVerifier(z);

	// save the state of this sigma protocol.
	doneFirstMsg = false;
}


/***************************/
/*   SigmaVerifier         */
/***************************/
bool SigmaVerifier::verify(SigmaCommonInput * input) {
	// samples the challenge.
	sampleChallenge();
	// sends the challenge.
	sendChallenge();
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
		throw IllegalStateException("sampleChallenge function should be called before sendChallenge");

	// send the challenge.
	sendChallengeToProver(challenge, challenge_size);

	// save the state of the protocol.
	doneChallenge = true;
}

bool SigmaVerifier::processVerify(SigmaCommonInput * input) {
	if (!doneChallenge)
		throw IllegalStateException("sampleChallenge and sendChallenge should be called before processVerify");
	// wait for second message from the prover.
	receiveMsgFromProver(z);
	// verify the proof
	bool verified = verifierComputation->verify(input, a, z);
	// save the state of the protocol.
	doneChallenge = false;
	return verified;
}

void SigmaVerifier::receiveMsgFromProver(SigmaProtocolMsg * msg) {
	auto v = channel->read_one();
	msg->init_from_byte_array(&(v->at(0)), v->size());
}