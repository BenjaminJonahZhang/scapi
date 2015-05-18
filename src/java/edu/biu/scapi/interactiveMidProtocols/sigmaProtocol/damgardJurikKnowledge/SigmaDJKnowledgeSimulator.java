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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikKnowledge;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of Sigma Simulator.<p>
 * This implementation simulates the case that the prover convinces a verifier that he knows the plaintext
 * and randomness corresponding to a Damg{\aa}rd-Jurik encryption<p>
 * 
 * This protocol is due to Cramer, Damg{\aa}rd, and Nielsen, "Multiparty Computation from Threshold Homomorphic Encryption"
 * 
 * @author Eindhoven University of Technology (Meilof Veeningen)
 *
 */
public class SigmaDJKnowledgeSimulator implements SigmaSimulator{
	
	/*	
	  This class computes the following calculations:
		  	SAMPLE random values d <- ZN, e <- ZN'
			COMPUTE B=(1+n)^d e^N Y^-e mod N'
			OUTPUT (B,c,(d,e,f))
	*/
	
	private int t; 					// Soundness parameter in BITS.
	private int lengthParameter;	// Length parameter in BITS.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDJKnowledgeSimulator(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJKnowledgeSimulator() {
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
		
		doConstruct(t, 1, new SecureRandom());
	}
	
	/**
	 * Sets the given parameters.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	private void doConstruct(int t, int lengthParameter, SecureRandom random){
		
		this.t = t;
		this.lengthParameter = lengthParameter;
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
	 * @param input MUST be an instance of SigmaDJProduct2CommonInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaDJProductCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input, byte[] challenge) throws CheatAttemptException{
		/*
		  	SAMPLE random values d <- ZN, e <- ZN'
			COMPUTE B=(1+n)^d e^N Y^-e mod N'
			OUTPUT (A,c,(d,e,f))
		 */
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		if (!(input instanceof SigmaDJKnowledgeCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJProductCommonInput");
		}
		SigmaDJKnowledgeCommonInput djInput = (SigmaDJKnowledgeCommonInput) input;
		 
		BigInteger n = djInput.getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundnessParam(n)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		//Calculate N = n^s and N' = n^(s+1)
		BigInteger N = n.pow(lengthParameter);
		BigInteger NTag = n.pow(lengthParameter + 1);
		
		//Sample a random value d <- ZN
		BigInteger d = BigIntegers.createRandomInRange(BigInteger.ZERO, N.subtract(BigInteger.ONE), random);
		//Sample a random value e <- Z*n
		BigInteger e = BigIntegers.createRandomInRange(BigInteger.ZERO, NTag.subtract(BigInteger.ONE), random);
		
		//Create the BigInteger value out of the challenge.
		BigInteger c = new BigInteger(1, challenge);
		
		// compute B=(1+n)^d e^N Y^-e mod N'
		
		BigInteger Np1ToD = n.add(BigInteger.ONE).modPow(d, NTag);
		BigInteger eToN = e.modPow(N, NTag);
		BigInteger YToMinusC = djInput.getCiphertextB().getCipher().modPow(c.negate(), NTag);
		BigInteger B = Np1ToD.multiply(eToN).mod(NTag).multiply(YToMinusC).mod(NTag);
		
		//Output (a,e,z).
		return new SigmaDJKnowledgeSimulatorOutput(new SigmaBIMsg(B), challenge, new SigmaDJKnowledgeSecondMsg(d, e));
				
	}
	
	/**
	 * Computes the simulator computation with a randomly chosen challenge.
	 * @param input MUST be an instance of SigmaDJProductInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaDJProductInput.
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
	 * Checks the validity of the given soundness parameter.
	 * t must be less than a third of the length of the public key n.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundnessParam(BigInteger modulus){
		//If soundness parameter is not less than a third of the publicKey n, return false.
		int third = modulus.bitLength() / 3;
		if (t >= third){
			return false;
		}
		return true;
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
