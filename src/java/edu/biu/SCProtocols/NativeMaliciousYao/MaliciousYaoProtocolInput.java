package edu.biu.SCProtocols.NativeMaliciousYao;

import edu.biu.scapi.comm.ProtocolInput;

/**
 * This class manage the input for the malicious Yao protocol. <p>
 * The input are the id of the party and the names of 1. the config file 2. the elliptic curves file. <p>
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class MaliciousYaoProtocolInput implements ProtocolInput {
	
	private int id;
	private String configFileName;
	
	public MaliciousYaoProtocolInput(int id, String configFileName){
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
