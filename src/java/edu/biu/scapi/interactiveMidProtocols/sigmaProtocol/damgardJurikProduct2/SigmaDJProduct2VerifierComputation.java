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

import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a party to prove that 3 ciphertexts c1,c2,c3 are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.<p>
 * 
 * This protocol is due to Cramer, Damg{\aa}rd, and Nielsen, "Multiparty Computation from Threshold Homomorphic Encryption"
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJProduct2VerifierComputation implements SigmaVerifierComputation, DJBasedSigma{

	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e -< {0, 1}^t 
			ACC IFF (1+n)^d e^N=BY^c mod N' and X^d f^N=AZ^c mod N'
        
	*/
	
	private int t; 						// Soundness parameter in BITS.
	private int lengthParameter;		// Length parameter in BITS.
	private SecureRandom random;
	private byte[] e;					// The challenge.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDJProduct2VerifierComputation(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJProduct2VerifierComputation() {
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
	 * Sets the input for this Sigma protocol.
	 * @param input MUST be an instance of SigmaDJProductCommonInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJProductCommonInput.
	 */
	private void checkInput(SigmaCommonInput input) {
		if (!(input instanceof SigmaDJProduct2CommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJProductInput");
		}
		
		BigInteger modulus = ((SigmaDJProduct2CommonInput) input).getPublicKey().getModulus();
		// Check the soundness validity.
		if (!checkSoundnessParam(modulus)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
	}
	
	/**
	 * Checks the validity of the given soundness parameter.<p>
	 * t must be less than a third of the length of the public key n.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundnessParam(BigInteger modulus){
		//If soundness parameter is not less than a third of the publicKey n, throw IllegalArgumentException.
		int third = modulus.bitLength() / 3;
		if (t >= third){
			return false;
		}
		return true;
	}
	
	/**
	 * Samples the challenge of the protocol.<p>
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
	 * Computes the verification of the protocol.<p>
	 * 	"ACC IFF (1+n)^d e^N=BY^c mod N' and X^d f^N=AZ^c mod N'
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if the first prover message is not an instance of SigmaDJProductFirstMsg
	 * @throws IllegalArgumentException if the second prover message is not an instance of SigmaDJProductSecondMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		checkInput(input);
		SigmaDJProduct2CommonInput djInput = (SigmaDJProduct2CommonInput) input;
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaDJProduct2FirstMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaDJProduct2FirstMsg");
		}
		if (!(z instanceof SigmaDJProduct2SecondMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaDJProduct2SecondMsg");
		}
		SigmaDJProduct2FirstMsg firstMsg = (SigmaDJProduct2FirstMsg) a;
		SigmaDJProduct2SecondMsg secondMsg = (SigmaDJProduct2SecondMsg) z;
		
		BigInteger n = djInput.getPublicKey().getModulus();
		BigInteger N = n.pow(lengthParameter);
		BigInteger NTag = n.pow(lengthParameter + 1);
		BigInteger c = new BigInteger(1, e);
		
		BigInteger A = firstMsg.getA1(), B = firstMsg.getA2();
		BigInteger d = secondMsg.getZ1(), e = secondMsg.getZ2(), f = secondMsg.getZ3(); 
		
		BigInteger Np1ToD = n.add(BigInteger.ONE).modPow(d,NTag);
		BigInteger eToN = e.modPow(N, NTag);
		BigInteger lhs1 = Np1ToD.multiply(eToN).mod(NTag);
		
		BigInteger yToC = djInput.getCiphertextB().getCipher().modPow(c, NTag);
		BigInteger rhs1 = B.multiply(yToC).mod(NTag);
		
		BigInteger XtoD = djInput.getCiphertextA().getCipher().modPow(d, NTag);
		BigInteger fToN = f.modPow(N, NTag);
		BigInteger lhs2 = XtoD.multiply(fToN).mod(NTag);
		
		BigInteger ZtoC = djInput.getCiphertextAB().getCipher().modPow(c, NTag);
		BigInteger rhs2 = A.multiply(ZtoC).mod(NTag);
		
		verified = verified && lhs1.equals(rhs1);
		verified = verified && lhs2.equals(rhs2);
		
		return verified;	
	}
}
