package edu.biu.SCProtocols.gmw;

import edu.biu.scapi.comm.ProtocolInput;

/**
 * This class manage the input for the GMW protocol. <p>
 * The input are the id of the party, the files contain the 1. circuit 2. parties data 3. inputs, 
 * and the number of threads to use in the protocol. <p>
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GmwProtocolInput implements ProtocolInput {

	private int id;
	private String circuitFileName;
	private String partiesFileName;
	private String inputsFileName;
	private int numOfThreads;
	
	public GmwProtocolInput(int id, String circuitFileName, String partiesFileName, String inputsFileName, int numOfThreads){
		this.circuitFileName = circuitFileName;
		this.partiesFileName = partiesFileName;
		this.inputsFileName = inputsFileName;
		this.id = id;
		this.numOfThreads = numOfThreads;
	}
	
	public int getID(){
		return id;
	}
	
	public String getCircuitFileName(){
		return circuitFileName;
	}
	
	public String getPartiesFileName(){
		return partiesFileName;
	}
	
	public String getInputsFileName(){
		return inputsFileName;
	}
	
	public int getNumOfThreads(){
		return numOfThreads;
	}
}
