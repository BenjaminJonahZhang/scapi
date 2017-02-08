package edu.biu.SCProtocols.gmw;

import edu.biu.scapi.comm.ProtocolOutput;

/**
 * This class manage the output for the GMW protocol. <p>
 * The output is a byte array represents the value of each output wire of the circuit. <p>
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GmwProtocolOutput implements ProtocolOutput {

	private byte[] output;
	
	public GmwProtocolOutput(byte[] output){
		this.output = output;
	}
	
	public byte[] getOutput(){
		return output;
	}
}
