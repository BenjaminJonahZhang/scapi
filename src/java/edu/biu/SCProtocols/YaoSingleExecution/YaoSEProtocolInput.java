package edu.biu.SCProtocols.YaoSingleExecution;

import edu.biu.scapi.comm.ProtocolInput;

public class YaoSEProtocolInput implements ProtocolInput {
	private int id;
	private String circuitFileName;
	private String ip;
	private int port;
	private String inputsFileName;
	
	public YaoSEProtocolInput(int id, String circuitFileName, String ip, int port, String inputsFileName){
		this.circuitFileName = circuitFileName;
		this.inputsFileName = inputsFileName;
		this.ip = ip;
		this.port = port;
		this.id = id;
	}
	
	public int getID(){
		return id;
	}
	
	public String getCircuitFileName(){
		return circuitFileName;
	}
	
	public String getIP(){
		return ip;
	}
	
	public String getInputsFileName(){
		return inputsFileName;
	}
	
	public int getPort(){
		return port;
	}
}
