package edu.biu.SCProtocols.NativeSemiHonestYao;

import edu.biu.scapi.comm.ProtocolInput;

public class YaoProtocolInput implements ProtocolInput {

	private int id;
	private int number_of_iterations;
	private String configFileName;
	
	public YaoProtocolInput(int number_of_iterations, int id, String configFileName){
		this.number_of_iterations = number_of_iterations;
		this.id = id;
		this.configFileName = configFileName;
	}
	
	public int getID(){
		return id;
	}
	
	public int getNumberOfIterations(){
		return number_of_iterations;
	}
	
	public String getConfigFileName(){
		return configFileName;
	}
}
