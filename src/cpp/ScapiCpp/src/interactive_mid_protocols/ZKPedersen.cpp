//#include "../../include/interactive_mid_protocols/ZKPedersen.hpp"
//
///************************************************/
///*   ZKPOKFromSigmaCmtPedersenProver            */
///************************************************/
//
//void ZKPOKFromSigmaCmtPedersenProver::prove(ZKProverInput* input) {
//	auto spi = dynamic_cast<SigmaProverInput*>(input);
//	// the given input must be an instance of SigmaProverInput.
//	if (!spi) 
//		throw invalid_argument("the given input must be an instance of SigmaProverInput");
//
//	// run the receiver in TRAP_COMMIT.commit 
//	CmtRCommitPhaseOutput* trap = receiveCommit();
//	// compute the first message a in sigma, using (x,w) as input and 
//	// send a to V
//	processFirstMsg(spi);
//	// run the receiver in TRAP_COMMIT.decommit 
//	// if decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
//	byte* e = receiveDecommit(trap->getCommitmentId());
//	// if decommit returns some e, compute the response z to (a,e) according to sigma, 
//	// send z to V and output nothing
//	processSecondMsg(e, trap);
//
//}
//
//void ZKPOKFromSigmaCmtPedersenProver::processSecondMsg(byte* e, int eSize,
//	CmtRCommitPhaseOutput* trap) { 
//	// compute the second message by the underlying proverComputation.
//	SigmaProtocolMsg* z = sProver->computeSecondMsg(e, eSize);
//
//	// send the second message.
//	sendMsgToVerifier(z, eSize);
//
//	// send the trap.
//	sendMsgToVerifier(trap, eSize);
//}
//
//CmtRCommitPhaseOutput* ZKPOKFromSigmaCmtPedersenProver::receiveCommit() {
//	CmtCommitValue* val = receiver->receiveDecommitment(id);
//	if (val == null) 
//		throw CheatAttemptException("Decommit phase returned invalid");
//	return receiver->generateBytesFromCommitValue(val);
//}
