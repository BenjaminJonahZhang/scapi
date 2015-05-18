/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2014 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dhExtendedStatistical;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * In this sigma protocol, the prover proves knowledge of y (of size N) s.t. y=log_u1 v1=log_u2 v2=...=log_un vn mod N
 * 
 * @author Eindhoven University of Technology (Meilof Veeningen)
 *
 */
public class SigmaDHExtendedStatisticalVerifierComputation implements SigmaVerifierComputation {

	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e <- {0, 1}^t 
			ACC IFF VALID_PARAMS(G,q,g)=TRUE AND all g1,..,gm in Z_N AND for all i=1,...,m it holds that gi^z = ai*hi^e mod N        
              
	*/	
	
	private int t; 							//Soundness parameter in BITS.
	private byte[] e;						//The challenge.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the soundness parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	public SigmaDHExtendedStatisticalVerifierComputation(int t, SecureRandom random)  {
		
		//Sets the parameters.
		this.t = t;
		this.random = random;
		
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return t;
	}
	
	/**
	 * Samples the challenge for this protocol.<p>
	 * 	"SAMPLE a random challenge e<-{0,1}^t".
	 */
	public void sampleChallenge(){
		//Create a new byte array of size t/8, to get the required byte size.
		e = new byte[t/8];
		//fills the byte array with random values.
		random.nextBytes(e);
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		e = challenge;
	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		return e;
	}

	/**
	 * Computes the protocol's verification.<p>
	 * Computes the following line from the protocol:<p>
	 * 	"ACC IFF VALID_PARAMS(G,q,g)=TRUE AND all g1,...,gm in ZN AND for all i=1,...,m it holds that gi^z = ai*hi^e mod N".   <p>  
	 * @param input MUST be an instance of SigmaDHExtendedStatisticalCommonInput.
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDHExtendedStatisticalCommonInput.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHExtendedStatisticalMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//the first check "ACC IFF VALID_PARAMS(G,q,g)=TRUE" is already done in the constructor.
		
		//Check the input.
		if (!(input instanceof SigmaDHExtendedStatisticalCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDHExtendedCommonInput");
		}
		
		SigmaDHExtendedStatisticalCommonInput dhInput = (SigmaDHExtendedStatisticalCommonInput) input;
		ArrayList<BigInteger> gArray = dhInput.getGArray();
		ArrayList<BigInteger> hArray = dhInput.getHArray();
		
		if (gArray.size() != hArray.size()){
			throw new IllegalArgumentException("the given g and h array are not in the same size");
		}
		
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaDHExtendedStatisticalMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaDHExtendedStatisticalMsg");
		}
		if (!(z instanceof SigmaBIMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaBIMsg");
		}
		
		
		//Get the g array from the input. 
		int len = gArray.size();
		
		//Verify that each gi is in Z_N.
		for (int i=0; i<len; i++) {
			verified = verified && gArray.get(i).compareTo(BigInteger.ZERO) >= 0 &&
					               gArray.get(i).compareTo(dhInput.getN()) < 0;
		}
		
		
		//Get the h and a arrays.
		SigmaDHExtendedStatisticalMsg firstMsg = (SigmaDHExtendedStatisticalMsg) a;
		ArrayList<BigInteger> aArray = firstMsg.getArray();
		//Get the exponent in the second message from the prover.
		SigmaBIMsg exponent = (SigmaBIMsg) z;
		//Convert e to BigInteger.
		BigInteger eBI = new BigInteger(1, e);
		BigInteger left, right;
		BigInteger hToe;
		BigInteger aElement;
		
		for (int i=0; i<len; i++){
			//Verify that gi^z = ai*hi^e:
			
			//Compute gi^z (left size of the equation).
			left = gArray.get(i).modPow(exponent.getMsg(), dhInput.getN());
			
			//Compute ai*hi^e (right side of the verify equation).
			//Calculate hi^e.
			hToe = hArray.get(i).modPow(eBI, dhInput.getN());
			//Calculate a*hi^e.
			aElement = aArray.get(i);
			right = aElement.multiply(hToe).mod(dhInput.getN());
			
			//If left and right sides of the equation are not equal, set verified to false.
			verified = verified && left.equals(right);
		}
		
		e = null; //Delete the random value e.
		
		//Return true if all checks returned true; false, otherwise.
		return verified;
	}
}
