package edu.biu.protocols.yao.primitives;

import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.scapi.comm.ProtocolOutput;

/**
 * 
 * This class manages the output of the circuit evaluation. <P>
 * 
 * It contains the output bit for each output wire.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CircuitOutput implements ProtocolOutput {
	private byte[] output;		//The output bit for each output wire.
	/**
	 * Constructor that sets the output for the output wires.
	 * @param outputWires The output bit for each output wire.
	 */
	public CircuitOutput(byte[] outputWires) {
		Preconditions.checkNotZero(outputWires.length);
		
		output = outputWires;
	}
	
	/**
	 * Returns the output bit of each output wires.
	 */
	public byte[] getOutput() {
		return output;
	}
}
