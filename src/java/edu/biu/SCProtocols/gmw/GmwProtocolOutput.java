package edu.biu.SCProtocols.gmw;

import edu.biu.scapi.comm.ProtocolOutput;

public class GmwProtocolOutput implements ProtocolOutput {

	private byte[] output;
	
	public GmwProtocolOutput(byte[] output){
		this.output = output;
	}
	
	public byte[] getOutput(){
		return output;
	}
}
