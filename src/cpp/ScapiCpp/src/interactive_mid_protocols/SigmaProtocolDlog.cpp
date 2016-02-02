#include "../../include/interactive_mid_protocols/SigmaProtocolDlog.hpp"

bool check_soundness(int t, DlogGroup* dlog) {
	// if soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

/***************************************/
/*   SigmaDlogSimulator                */
/***************************************/

SigmaDlogSimulator::SigmaDlogSimulator(DlogGroup* dlog, int t, std::mt19937 random) {
	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q. q=" +
			(string)dlog->getOrder() + " t=" + to_string(t) + "\n");
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;
}

SigmaSimulatorOutput* SigmaDlogSimulator::simulate(SigmaCommonInput* input, 
	byte* challenge, int challenge_size) {
	//check the challenge validity.
	if (!checkChallengeLength(challenge, challenge_size))
		throw CheatAttemptException(
			"the length of the given challenge is different from the soundness parameter");
	SigmaDlogCommonInput* dlogInput = (SigmaDlogCommonInput*)input;

	// SAMPLE a random z <- Zq
	biginteger z = getRandomInRange(0, qMinusOne, random);

	// COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)
	GroupElement* gToZ = dlog->exponentiate(dlog->getGenerator(), z);
	biginteger e = decodeBigInteger(challenge, challenge_size);
	biginteger minusE = dlog->getOrder() - e;
	GroupElement* hToE = dlog->exponentiate(dlogInput->getH(), minusE);
	GroupElement* a = dlog->multiplyGroupElements(gToZ, hToE);

	// OUTPUT (a,e,eSize,z).
	return new SigmaDlogSimulatorOutput(new SigmaGroupElementMsg(a->generateSendableData()),
		challenge, challenge_size, new SigmaBIMsg(z));
}

SigmaSimulatorOutput* SigmaDlogSimulator::simulate(SigmaCommonInput* input) {
	byte* e = new byte[t / 8]; // create a new byte array of size t/8, to get the required byte size.
	if (!RAND_bytes(e, t / 8)) // fill the byte array with random values.
		throw runtime_error("key generation failed");

	// call the other simulate function with the given input and the sampled e.
	return simulate(input, e, t/8);
}

bool SigmaDlogSimulator::checkSoundnessParam() {
	return check_soundness(t, dlog);
}

/***************************************/
/*   SigmaDlogProverComputation        */
/***************************************/

SigmaDlogProverComputation::SigmaDlogProverComputation(DlogGroup* dlog,
	int t, std::mt19937 random) {
	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;
}

SigmaProtocolMsg* SigmaDlogProverComputation::computeFirstMsg(SigmaProverInput* input) {
	this->input = (SigmaDlogProverInput*)input;
	// sample random r in Zq
	r = getRandomInRange(0, qMinusOne, random);
	// compute a = g^r.
	GroupElement* a = dlog->exponentiate(dlog->getGenerator(), r);
	auto x = a->generateSendableData();
	// create and return SigmaGroupElementMsg with a.
	return new SigmaGroupElementMsg(x);

}

SigmaProtocolMsg* SigmaDlogProverComputation::computeSecondMsg(byte* challenge,
	int challenge_size) {
	if (!checkChallengeLength(challenge, challenge_size)) // check the challenge validity.
		throw CheatAttemptException(
			"the length of the given challenge is different from the soundness parameter");

	// compute z = (r+ew) mod q
	biginteger q = dlog->getOrder();
	biginteger e = decodeBigInteger(challenge, challenge_size);
	biginteger ew = (e * input->getW()) % q;
	biginteger z = (r + ew) % q;
	
	// create and return SigmaBIMsg with z
	return new SigmaBIMsg(z);
}

bool SigmaDlogProverComputation::checkSoundnessParam() {
	return check_soundness(t, dlog);
}

/***************************************/
/*   SigmaDlogVerifierComputation      */
/***************************************/

SigmaDlogVerifierComputation::SigmaDlogVerifierComputation(DlogGroup* dlog, 
	int t, std::mt19937 random) {
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("invalid dlog");

	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	this->random = random;
}

void SigmaDlogVerifierComputation::sampleChallenge() {
	biginteger e_number = getRandomInRange(0, mp::pow(biginteger(2), t) - 1, random);
	cout << "sampled challenge between 0 and: " << mp::pow(biginteger(2), t)-1 << 
		" got: " << e_number << endl;
	eSize = bytesCount(e_number);
	e = new byte[eSize]; // create a new byte array of size t/8, to get the required byte size.
	encodeBigInteger(e_number, e, eSize);
}

bool SigmaDlogVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a,
	SigmaProtocolMsg* z) {
	SigmaDlogCommonInput* cInput = (SigmaDlogCommonInput*)input;
	bool verified = true;
	SigmaGroupElementMsg* firstMsg = (SigmaGroupElementMsg*)a;
	SigmaBIMsg* exponent = (SigmaBIMsg*)z;

	GroupElement* aElement = dlog->reconstructElement(true, firstMsg->getElement());

	// get the h from the input and verify that it is in the Dlog Group.
	GroupElement* h = cInput->getH();
	// if h is not member in the group, set verified to false.
	verified = verified && dlog->isMember(h);

	// compute g^z (left size of the verify equation).
	GroupElement * left = dlog->exponentiate(dlog->getGenerator(), exponent->getMsg());

	// compute a*h^e (right side of the verify equation).
	biginteger eBI = decodeBigInteger(e, eSize); 	// convert e to biginteger.
	GroupElement* hToe = dlog->exponentiate(h, eBI); // calculate h^e.

	// calculate a*h^e.
	GroupElement* right = dlog->multiplyGroupElements(aElement, hToe);

	// if left and right sides of the equation are not equal, set verified to false.
	verified = verified && (*left==*right);

	delete e;
	eSize = 0;

	// return true if all checks returned true; false, otherwise.
	return verified;
}

bool SigmaDlogVerifierComputation::checkSoundnessParam() {
	return check_soundness(t, dlog);
}