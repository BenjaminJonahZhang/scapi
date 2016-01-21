#include "../../include/interactive_mid_protocols/SigmaProtocolAnd.hpp"


/***************************************/
/*   SigmaANDProverInput               */
/***************************************/
SigmaCommonInput* SigmaANDProverInput::getCommonParams() {
	/*
	* There are two options to implement this function:
	* 1. Create a new instance of SigmaANDCommonInput every time the function is called.
	* 2. Create the object in the construction time and return it every time this function is called.
	* This class holds an array of SigmaProverInput, where each instance in the array holds
	* an instance of SigmaCommonParams inside it.
	* In the second option above, this class will have in addition an array of SigmaCommonInput.
	* This way, the SigmaCommonInput instances will appear twice -
	* once in the array and once in the corresponding SigmaProverInput.
	* This is an undesired duplication and redundancy, So we decided to implement using the
	* first way, although this is less efficient.
	* In case the efficiency is important, a user can derive this class and override this implementation.
	*/
	vector<SigmaCommonInput*> paramsArr;
	for(auto sigmaInput : sigmaInputs)
		paramsArr.push_back(sigmaInput->getCommonParams());

	return new SigmaANDCommonInput(paramsArr);
}

/***************************************/
/*   SigmaANDProverComputation         */
/***************************************/

SigmaANDProverComputation::SigmaANDProverComputation(vector<SigmaProverComputation *> provers, int t, mt19937 random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for (auto prover : provers)
		if(t != prover->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying provers objects.");

	this->provers = provers;
	len = provers.size();
	this->t = t;
	this->random = random;
}

SigmaProtocolMsg * SigmaANDProverComputation::computeFirstMsg(SigmaProverInput *in) {
	// checks that the input is as expected.
	SigmaANDProverInput * input = checkInput(in);
	vector<SigmaProverInput *> proversInput = input->getInputs();

	// create an array to hold all messages.
	vector<SigmaProtocolMsg *> firstMessages;

	// compute all first messages and add them to the array list.
	for (int i = 0; i < len; i++) 
		firstMessages.push_back(provers[i]->computeFirstMsg(proversInput[i]));

	// create a SigmaMultipleMsg with the messages array.
	return new SigmaMultipleMsg(firstMessages);
}

SigmaProtocolMsg * SigmaANDProverComputation::computeSecondMsg(byte* challenge, int challenge_size) {
	// create an array to hold all messages.
	vector<SigmaProtocolMsg *> secondMessages;
	// compute all second messages and add them to the array list.
	for(auto prover : provers)
		secondMessages.push_back(prover->computeSecondMsg(challenge, challenge_size));

	// Create a SigmaMultipleMsg with the messages array.
	return new SigmaMultipleMsg(secondMessages);
}

SigmaSimulator* SigmaANDProverComputation::getSimulator() {
	vector<SigmaSimulator*> simulators;
	for(auto prover:provers)
		simulators.push_back(prover->getSimulator());
	return new SigmaANDSimulator(simulators, t, random);
}

SigmaANDProverInput * SigmaANDProverComputation::checkInput(SigmaProverInput * in) {
	SigmaANDProverInput *input = dynamic_cast<SigmaANDProverInput*>(in);
	if (!input)
		throw invalid_argument("the given input must be an instance of SigmaANDProverInput");

	int inputLen = input->getInputs().size();

	// if number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len)
		throw invalid_argument("number of inputs is different from number of underlying provers.");
	return input;
}

/***************************************/
/*   SigmaANDSimulator                 */
/***************************************/

SigmaANDSimulator::SigmaANDSimulator(vector<SigmaSimulator *> simulators, int t, mt19937 random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto sigmaSimulator : simulators)
		if(t!=sigmaSimulator->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying simulators objects.");

	this->simulators = simulators;
	len = simulators.size();
	this->t = t;
	this->random = random;
}

SigmaSimulatorOutput* SigmaANDSimulator::simulate(SigmaCommonInput *input, byte* challenge, int challenge_size) {
	if (!checkChallengeLength(challenge_size)) 
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	
	SigmaANDCommonInput *andInput = (SigmaANDCommonInput *)input;

	vector<SigmaCommonInput*> simulatorsInput = andInput->getInputs();
	int inputLen = simulatorsInput.size();

	// if number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len) 
		throw invalid_argument("number of inputs is different from number of underlying simulators.");

	vector<SigmaProtocolMsg*> aOutputs;
	vector<SigmaProtocolMsg*> zOutputs;
	SigmaSimulatorOutput *output = NULL;
	// run each Sigma protocol simulator with the given challenge.
	for (int i = 0; i < len; i++) {
		output = simulators[i]->simulate(simulatorsInput[i], challenge, challenge_size);
		aOutputs.push_back(output->getA());
		zOutputs.push_back(output->getZ());
	}

	// create a SigmaMultipleMsg from the simulates function's outputs to create a and z.
	SigmaMultipleMsg * a = new SigmaMultipleMsg(aOutputs);
	SigmaMultipleMsg * z = new SigmaMultipleMsg(zOutputs);

	// output (a,e,eSize,z).
	return new SigmaANDSimulatorOutput(a, challenge, challenge_size, z);
}

SigmaSimulatorOutput* SigmaANDSimulator::simulate(SigmaCommonInput *input) {
	// create a new byte array of size t/8, to get the required byte size.
	byte* e = new byte[t / 8];
	// fill the byte array with random values.
	if (!RAND_bytes(e, t / 8 ))
		throw runtime_error("key generation failed");
	// call the other simulate function with the given input and the samples e.
	return simulate(input, e, t / 8);
}


/***************************************/
/*   SigmaANDVerifierComputation       */
/***************************************/
SigmaANDVerifierComputation::SigmaANDVerifierComputation(vector<SigmaVerifierComputation*> & verifiers, int t, std::mt19937 random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto verifier : verifiers)
		if(t != verifier->getSoundnessParam())
			throw new invalid_argument("the given t does not equal to one of the t values in the underlying verifiers objects.");

	this->verifiers = verifiers;
	len = verifiers.size();
	this->t = t;
	this->random = random;
}

void SigmaANDVerifierComputation::sampleChallenge() {
	// create a new byte array of size t/8, to get the required byte size.
	e = new byte[t / 8];
	// fill the byte array with random values.
	if (!RAND_bytes(e, t / 8))
		throw runtime_error("key generation failed");

	// set all the other verifiers with the sampled challenge.
	for (auto verifier : verifiers)
		verifier->setChallenge(e, t / 8);
}

bool SigmaANDVerifierComputation::verify(SigmaCommonInput * input, SigmaProtocolMsg * a, SigmaProtocolMsg * z) {
	// checks that the input is as expected.
	checkInput(input);
	vector<SigmaCommonInput *> verifiersInput = ((SigmaANDCommonInput *)input)->getInputs();

	bool verified = true;

	// if one of the messages is illegal, throw exception.
	SigmaMultipleMsg *first = dynamic_cast<SigmaMultipleMsg*>(a);
	SigmaMultipleMsg *second = dynamic_cast<SigmaMultipleMsg*>(z);
	if (!a)
		throw invalid_argument("first message must be an instance of SigmaMultipleMsg");
	if (!z)
		throw invalid_argument("second message must be an instance of SigmaMultipleMsg");

	vector<SigmaProtocolMsg*> firstMessages  = first ->getMessages();
	vector<SigmaProtocolMsg*> secondMessages = second->getMessages();

	//Compute all verifier checks.
	for (int i = 0; i < len; i++) 
		verified = verified && verifiers[i]->verify(verifiersInput[i], firstMessages[i], secondMessages[i]);

	// return true if all verifiers returned true; false, otherwise.
	return verified;
}

void SigmaANDVerifierComputation::checkInput(SigmaCommonInput* in) {
	SigmaANDCommonInput* input = (SigmaANDCommonInput*)in;
	int inputLen = input->getInputs().size();

	// if number of inputs is not equal to number of verifiers, throw exception.
	if (inputLen != len) {
		throw invalid_argument("number of inputs is different from number of underlying verifiers.");
	}
}