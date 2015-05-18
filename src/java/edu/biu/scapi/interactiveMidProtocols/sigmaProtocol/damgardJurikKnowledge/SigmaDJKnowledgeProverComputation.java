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
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;


/**
 * Concrete implementation of Sigma Protocol prover computation.<p>
 * 
 * This protocol is used for a party to prove knowledge of the plaintext and randomness of a Damg{\aa}rd-Jurik ciphertext.<p>
 * 
 * This protocol is due to Cramer, Damg{\aa}rd, and Nielsen, "Multiparty Computation from Threshold Homomorphic Encryption"
 * 
 * @author Eindhoven University of Technology (Meilof Veeningen)
 *
 */
public class SigmaDJKnowledgeProverComputation implements SigmaProverComputation, DJBasedSigma{
	/*	
	  This class computes the following calculations:
	        SAMPLE random values a <- ZN, u <- Z*n
	        COMPUTE B=(1+n)^a u^N'
	        COMPUTE t=floor((a+cy)/N), d=a+cy mod N, e=u r^c (1+n)^t mod N'  
	*/	
	
	private int t; 								// Soundness parameter in BITS.
	private int lengthParameter;				// Length parameter.
	private SecureRandom random;
	private SigmaDJKnowledgeProverInput input;	// Contains n, ciphertext, plaintext and randomness
	private BigInteger n;						// Modulus
	private BigInteger N, NTag;					// N = n^lengthParameter and N' = n^(lengthParameter+1).
	private BigInteger a, u;                    // The random values chosen in the protocol.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDJKnowledgeProverComputation(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJKnowledgeProverComputation() {
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
	 * Sets the input for this Sigma protocol
	 * @param input MUST be an instance of SigmaDJKnowledgeProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJKnowledgeProverInput.
	 */
	private void checkInput(SigmaProverInput input) {
		if (!(input instanceof SigmaDJKnowledgeProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJKnowledgeProverInput");
		}
		
		BigInteger modulus = ((SigmaDJKnowledgeProverInput) input).getCommonParams().getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundnessParam(modulus)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		this.input = (SigmaDJKnowledgeProverInput) input;
		n = modulus;
		
		//Calculate N = n^s and N' = n^(s+1)
		N = n.pow(lengthParameter);
		NTag = n.pow(lengthParameter + 1);
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
	 * Implements the following pseudocode:
	 * "SAMPLE random values a <- ZN, u <- Z*n"
	 */
	private void sampleRandomValues() {
		//Sample a <-[0, ..., N-1]
		a = BigIntegers.createRandomInRange(BigInteger.ZERO, N.subtract(BigInteger.ONE), random);
		
		//Sample u <-[1, ..., n-1]
		u = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
	}

	/**
	 * Computes the first message of the protocol.<p>
	 * 	 SAMPLE random values a <- ZN, u <- Z*n
	 *   COMPUTE B=(1+n)^a u^N'
	 * @param input MUST be an instance of SigmaDJKnowledgeProverInput.
	 * @return the computed message
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJProduct2ProverInput.
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput input) {
		checkInput(input);
		
		sampleRandomValues();
		
		BigInteger nPlusOne = n.add(BigInteger.ONE);
		BigInteger nPlusOneToA = nPlusOne.modPow(a, NTag);
		BigInteger uToN = u.modPow(N,  NTag);
		BigInteger B = nPlusOneToA.multiply(uToN).mod(NTag);
		
		//Create and return SigmaDJProductFirstMsg with a1 and a2.
		return new SigmaBIMsg(B);
		
	}

	/**
	 * Computes the second message of the protocol.<p>
	 * "COMPUTE t=floor((a+cy)/N), d=a+cy mod N, e=u r^c (1+n)^t mod N'".
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		BigInteger c = new BigInteger(1, challenge);
		BigInteger nPlusOne = n.add(BigInteger.ONE);
		
		BigInteger cy = c.multiply(input.getPlainB().getX());
		BigInteger dp = a.add(cy);
		
		BigInteger[] td = dp.divideAndRemainder(N);
		
		BigInteger rc = input.getRB().modPow(c, NTag);
		BigInteger Np1toT = nPlusOne.modPow(td[0], NTag);
		BigInteger e = u.multiply(rc).mod(NTag).multiply(Np1toT).mod(NTag);
		
		//Delete the random values
		a = BigInteger.ZERO;
		u = BigInteger.ZERO;
		
		return new SigmaDJKnowledgeSecondMsg(td[1], e);
	}
	
	/**
	 * Checks if the given challenge length is equal to the soundness parameter.
	 * @return true if the challenge length is t; false, otherwise. 
	 */
	private boolean checkChallengeLength(byte[] challenge){
		//If the challenge's length is equal to t, return true. else, return false.
		return (challenge.length == (t/8) ? true : false);
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaDamgardJurikProductSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaDJKnowledgeSimulator(t, lengthParameter, random);
	}
}
