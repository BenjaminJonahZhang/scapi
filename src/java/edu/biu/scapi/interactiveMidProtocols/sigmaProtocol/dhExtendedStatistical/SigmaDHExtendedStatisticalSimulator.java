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

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of Sigma Simulator.<p>
 * Simulates proof of knowledge of y (of size N) s.t. y=log_u1 v1=log_u2 v2=...=log_un vn mod N
 * 
 * @author Eindhoven University of Technology (Meilof Veeningen)
 *
 */
public class SigmaDHExtendedStatisticalSimulator implements SigmaSimulator{
	/*	
	  This class computes the following calculations:
		  	SAMPLE a random z of size log(N)+t
			For every i=1,...,m, COMPUTE ai = gi^z*hi^(-e) mod N
			OUTPUT ((a1,...,am),e,z)
	*/

	private int t;					//Soundness parameter.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the soundness parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	public SigmaDHExtendedStatisticalSimulator(int t, SecureRandom random){
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
	 * Computes the simulator computation with the given challenge.
	 * @param input MUST be an instance of SigmaDHExtendedCommonInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaDHExtendedCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input, byte[] challenge) throws CheatAttemptException{
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		if (!(input instanceof SigmaDHExtendedStatisticalCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDHExtendedCommonInput");
		}
		SigmaDHExtendedStatisticalCommonInput dhInput = (SigmaDHExtendedStatisticalCommonInput) input;
		
		//Get the array from the input.
		ArrayList<BigInteger> gArray = dhInput.getGArray();
		ArrayList<BigInteger> hArray = dhInput.getHArray();
		int size = dhInput.getGArray().size();
		
		//Check that the arrays are in the same size.
		if (size != hArray.size()){
			throw new IllegalArgumentException("the given g and h array are not in the same size");
		}
		
		//Sample a random z
		BigInteger z = new BigInteger(dhInput.getN().bitLength()+2*t, random);
		
		BigInteger e = new BigInteger(1, challenge);
		BigInteger minuse = e.negate();
		
		ArrayList<BigInteger> aArray = new ArrayList<BigInteger>();
		BigInteger gToZ;
		BigInteger hToE;
		BigInteger a;
		//For every i=1,�,m, Compute ai = gi^z*hi^(-e) 
		for (int i=0; i<size; i++){
			
			gToZ = gArray.get(i).modPow(z, dhInput.getN());
			hToE = hArray.get(i).modPow(minuse, dhInput.getN());
			a = gToZ.multiply(hToE).mod(dhInput.getN());
			aArray.add(a);
		}
		
		//Output ((a,b),e,z).
		return new SigmaDHExtendedStatisticalSimulatorOutput(new SigmaDHExtendedStatisticalMsg(aArray), challenge, new SigmaBIMsg(z));
				
	}
	
	/**
	 * Computes the simulator computation with randomly chosen challenge.
	 * @param input MUST be an instance of SigmaDHExtendedInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaDHExtendedInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input){
		//Create a new byte array of size t/8, to get the required byte size.
		byte[] e = new byte[t/8];
		//Fill the byte array with random values.
		random.nextBytes(e);
		//Call the other simulate function with the given input and the sampled e.
		try {
			return simulate(input, e);
		} catch (CheatAttemptException e1) {
			//will not occur since the challenge length is valid.
		}
		return null;
	}
	
	/**
	 * Checks if the given challenge length is equal to the soundness parameter.
	 * @return true if the challenge length is t; false, otherwise. 
	 */
	private boolean checkChallengeLength(byte[] challenge){
		//If the challenge's length is equal to t, return true. else, return false.
		return (challenge.length == (t/8) ? true : false);
	}

}
