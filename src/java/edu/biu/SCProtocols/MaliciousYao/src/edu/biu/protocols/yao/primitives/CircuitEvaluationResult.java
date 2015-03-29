package edu.biu.protocols.yao.primitives;

/**
 * Enum structure that defines possible outputs of circuit evaluation. <P>
 * The outputs of multiple circuits computations can be equal to each other or vary. 
 * VALID_OUTPUT is the case when all circuits output the same result.
 * INVALID_WIRE_FOUND is the case when there is a problem during the output processing.
 * FOUND_PROOF_OF_CHEATING is the case when there is at least one output that differs from the other output values.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public enum CircuitEvaluationResult {
	VALID_OUTPUT, 				// All circuits output the same result.
	INVALID_WIRE_FOUND, 		// There was a problem during the output processing.
	FOUND_PROOF_OF_CHEATING		// There is at least one output that differs from the other output values.
	
}
