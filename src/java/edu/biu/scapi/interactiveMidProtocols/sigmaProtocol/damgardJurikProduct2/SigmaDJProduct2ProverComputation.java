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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct2;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;


/**
 * Concrete implementation of Sigma Protocol prover computation.<p>
 * 
 * This protocol is used for a party to prove that 3 ciphertexts c1,c2,c3 are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.
 * The prover knows the plaintext and randomness of the second plaintext, and the randomness used to blind the resulting encryption.<p>
 * 
 * This protocol is due to Cramer, Damg{\aa}rd, and Nielsen, "Multiparty Computation from Threshold Homomorphic Encryption"
 * 
 * @author Eindhoven University of Technology (Meilof Veeningen)
 *
 */
public class SigmaDJProduct2ProverComputation implements SigmaProverComputation, DJBasedSigma{
	/*	
	  This class computes the following calculations:
	        SAMPLE random values a <- ZN, u,v <- Z*n
	        COMPUTE A=X^a v^N mod N', B=(1+n)^a u^N'
	        COMPUTE t=floor((a+cy)/N), d=a+cy mod N, e=u r^c (1+n)^t mod N', f=v X^t s^c mod N'  
	*/	
	
	private int t; 								// Soundness parameter in BITS.
	private int lengthParameter;				// Length parameter.
	private SecureRandom random;
	private SigmaDJProduct2ProverInput input;	// Contains n, 3 ciphertexts, 1 plaintext and 2 random values used to encrypt
	private BigInteger n;						// Modulus
	private BigInteger N, NTag;					// N = n^lengthParameter and N' = n^(lengthParameter+1).
	private BigInteger a, u, v;                 // The random values chosen in the protocol.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDJProduct2ProverComputation(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJProduct2ProverComputation() {
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
	 * @param input MUST be an instance of SigmaDJProductProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJProductProverInput.
	 */
	private void checkInput(SigmaProverInput input) {
		if (!(input instanceof SigmaDJProduct2ProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJProduct2ProverInput");
		}
		
		BigInteger modulus = ((SigmaDJProduct2ProverInput) input).getCommonParams().getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundnessParam(modulus)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		this.input = (SigmaDJProduct2ProverInput) input;
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
	 * "SAMPLE random values a <- ZN, u <- Z*n, v <- Z*n"
	 */
	private void sampleRandomValues() {
		//Sample a <-[0, ..., N-1]
		a = BigIntegers.createRandomInRange(BigInteger.ZERO, N.subtract(BigInteger.ONE), random);
		
		//Sample u, v <-[1, ..., n-1]
		u = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
		v = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
	}

	/**
	 * Computes the first message of the protocol.<p>
	 * 	 SAMPLE random values a <- ZN, u,v <- Z*n
	 *   COMPUTE A=X^a v^N mod N', B=(1+n)^a u^N'
	 * @param input MUST be an instance of SigmaDJProduct2ProverInput.
	 * @return the computed message
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJProduct2ProverInput.
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput input) {
		checkInput(input);
		
		SigmaDJProduct2ProverInput pi = (SigmaDJProduct2ProverInput) input;
		
		sampleRandomValues();
		
		BigInteger xToA = pi.getCommonParams().getCiphertextA().getCipher().modPow(a, NTag);
		BigInteger vToN = v.modPow(N, NTag);
		BigInteger A = xToA.multiply(vToN).mod(NTag);
		
		BigInteger nPlusOne = n.add(BigInteger.ONE);
		BigInteger nPlusOneToA = nPlusOne.modPow(a, NTag);
		BigInteger uToN = u.modPow(N,  NTag);
		BigInteger B = nPlusOneToA.multiply(uToN).mod(NTag);
		
		//Create and return SigmaDJProductFirstMsg with a1 and a2.
		return new SigmaDJProduct2FirstMsg(A, B);
		
	}

	/**
	 * Computes the second message of the protocol.<p>
	 * "COMPUTE t=floor((a+cy)/N), d=a+cy mod N, e=u r^c (1+n)^t mod N', f=v X^t s^c mod N'".
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
		
		BigInteger xToT = input.getCommonParams().getCiphertextA().getCipher().modPow(td[0], NTag);
		BigInteger sToC = input.getRAB().modPow(c,  NTag);
		BigInteger f = v.multiply(xToT).mod(NTag).multiply(sToC).mod(NTag);
		
		//Delete the random values
		a = BigInteger.ZERO;
		u = BigInteger.ZERO;
		v = BigInteger.ZERO;
		
		return new SigmaDJProduct2SecondMsg(td[1], e, f);
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
		return new SigmaDJProduct2Simulator(t, lengthParameter, random);
	}
}
