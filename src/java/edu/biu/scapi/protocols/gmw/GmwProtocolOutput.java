package edu.biu.scapi.protocols.gmw;

import edu.biu.scapi.protocols.ProtocolOutput;

public class GmwProtocolOutput implements ProtocolOutput {

	private byte[] output;
	
	public GmwProtocolOutput(byte[] output){
		this.output = output;
	}
	
	public byte[] getOutput(){
		return output;
	}
}
