package edu.biu.SCProtocols.NativeSemiHonestYao;

import edu.biu.scapi.comm.ProtocolInput;

/**
 * This class manage the input for the Yao protocol. <p>
 * The input are the id of the party and the name of the config file. <p>
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class YaoProtocolInput implements ProtocolInput {

	private int id;
	private String configFileName; //Contains the 
	
	public YaoProtocolInput(int id, String configFileName){
		this.id = id;
		this.configFileName = configFileName;
	}
	
	public int getID(){
		return id;
	}
	
	public String getConfigFileName(){
		return configFileName;
	}
}
