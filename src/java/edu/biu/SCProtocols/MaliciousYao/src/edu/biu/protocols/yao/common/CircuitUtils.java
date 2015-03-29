package edu.biu.protocols.yao.common;

import java.util.ArrayList;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.exceptions.NoSuchPartyException;

/**
 * This class provides some utilities regarding the circuits in order to use in the protocol. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CircuitUtils {
	
	/**
	 * Returns the input indices of the given party in the given circuit.
	 * @param bc The boolean circuit to get the input indices of.
	 * @param party The number of the party we want his input indices.
	 */
	public static ArrayList<Integer> getLabels(BooleanCircuit bc, int party) {
		Preconditions.checkIntegerInRange(party, 1, 2);
		try {
			return bc.getInputWireIndices(party);
		} catch (NoSuchPartyException e) {
			// should not happen because we already checked it.
		}
		throw new IllegalStateException();
	}
}
