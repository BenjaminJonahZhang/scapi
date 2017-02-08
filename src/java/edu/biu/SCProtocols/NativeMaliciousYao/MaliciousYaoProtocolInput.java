package edu.biu.SCProtocols.NativeMaliciousYao;

import edu.biu.scapi.comm.ProtocolInput;

public class MaliciousYaoProtocolInput implements ProtocolInput {
	
	private int id;
	private String configFileName;
	private String ecFileName;
	
	public MaliciousYaoProtocolInput(int id, String configFileName, String ecFileName){
		this.id = id;
		this.configFileName = configFileName;
		this.ecFileName = ecFileName;
	}
	
	public int getID(){
		return id;
	}
	
	public String getConfigFileName(){
		return configFileName;
	}
	
	public String getECFileName(){
		return ecFileName;
	}
}
