package edu.biu.protocols.yao.offlineOnline.subroutines;

import edu.biu.protocols.yao.primitives.CircuitEvaluationResult;

/**
 * An interface that provides functionality regarding the circuit evaluation. <P>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public interface ComputeCircuitsRoutine {
	
	/**
	 * Computes the inline circuits.
	 */
	public void computeCircuits();
	
	/**
	 * After evaluating the circuits, an output analysis should be executed in order to detect cheating.
	 * In case of cheating, a proof of the cheating is achieved and saved in the derived object.
	 * @return CircuitEvaluationResult Contains one of the folowing three posibilities:
	 * 								1. VALID_OUTPUT
	 * 								2. INVALID_WIRE_FOUND
	 * 								3. FOUND_PROOF_OF_CHEATING.
	 */
	public CircuitEvaluationResult runOutputAnalysis();
	
	/**
	 * Returns the output of the circuits.
	 */
	public byte[] getOutput();
}
