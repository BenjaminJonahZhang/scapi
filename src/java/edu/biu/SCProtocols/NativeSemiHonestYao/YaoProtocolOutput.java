package edu.biu.SCProtocols.NativeSemiHonestYao;

import edu.biu.scapi.comm.ProtocolOutput;

public class YaoProtocolOutput implements ProtocolOutput {

	private byte[] output;
	
	public YaoProtocolOutput(byte[] output){
		this.output = output;
	}
	
	public byte[] getOutput(){
		return output;
	}
}
