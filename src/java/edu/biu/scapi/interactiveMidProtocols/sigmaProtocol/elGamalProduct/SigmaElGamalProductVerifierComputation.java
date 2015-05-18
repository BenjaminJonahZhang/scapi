/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalProduct;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a committer to prove that the value committed to in the commitment (h,c1, c2) is x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalProductVerifierComputation implements SigmaVerifierComputation, DlogBasedSigma{
	private DlogGroup dlog;
	private int t;
	private SecureRandom random;
	
	private byte[] e;
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 */
	public SigmaElGamalProductVerifierComputation(DlogGroup dlog, int t, SecureRandom random) {
		this.dlog = dlog;
		this.t = t;
		this.random = random;
	}
	
	public SigmaElGamalProductVerifierComputation(DlogGroup dlog, SecureRandom random) {
		this.dlog = dlog;
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		this.t = Integer.parseInt(statisticalParameter);
		this.random = random;
	}
	
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return t;
	}

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
	 * Verifies the proof.
	 * @param z second message from prover
	 * @param input MUST be an instance of SigmaElGamalCommittedValueCommonInput.
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaElGamalCommittedValueCommonInput.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		if (!(input instanceof SigmaElGamalProductCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalCorrectMultiplicationCommonInput");
		}
		SigmaElGamalProductCommonInput dhInput = (SigmaElGamalProductCommonInput) input;
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaElGamalProductAnnouncement)){
			throw new IllegalArgumentException("first message must be an instance of SigmaElGamalCorrectMultiplicationAnnouncement");
		}
		if (!(z instanceof SigmaElGamalProductSecondMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaElGamalProductSecondMsg");
		}
		
		//Get the elements of the first message from the prover.
		SigmaElGamalProductAnnouncement m1 = (SigmaElGamalProductAnnouncement) a;
		SigmaElGamalProductSecondMsg m2 = (SigmaElGamalProductSecondMsg) z;
		
		GroupElement a1 = dlog.reconstructElement(false, m1.getA1());
		GroupElement a2 = dlog.reconstructElement(false, m1.getA2());
		GroupElement a3 = dlog.reconstructElement(false, m1.getA3());
		GroupElement a4 = dlog.reconstructElement(false, m1.getA4());

		GroupElement g = dlog.getGenerator(),
				     h = dhInput.getPublicKey().getH(),
				     A1 = dhInput.getA().getC1(), 
				     A2 = dhInput.getA().getC2(),
				     B1 = dhInput.getB().getC1(),
				     B2 = dhInput.getB().getC2(),
				     C1 = dhInput.getAB().getC1(),
				     C2 = dhInput.getAB().getC2();
		
		BigInteger R1 = m2.getZ1(),
				   R2 = m2.getZ2(),
				   R3 = m2.getZ3();

		BigInteger eBI = new BigInteger(1, e);
		
		GroupElement l1 = dlog.exponentiate(g, R1);
		GroupElement l2 = dlog.multiplyGroupElements(dlog.exponentiate(h, R1), dlog.exponentiate(g, R2));
		GroupElement l3 = dlog.multiplyGroupElements(dlog.exponentiate(A1, R2), dlog.exponentiate(g, R3));
		GroupElement l4 = dlog.multiplyGroupElements(dlog.exponentiate(A2, R2), dlog.exponentiate(h, R3));
		
		GroupElement r1 = dlog.multiplyGroupElements(a1, dlog.exponentiate(B1,  eBI));
		GroupElement r2 = dlog.multiplyGroupElements(a2, dlog.exponentiate(B2,  eBI));
		GroupElement r3 = dlog.multiplyGroupElements(a3, dlog.exponentiate(C1,  eBI));
		GroupElement r4 = dlog.multiplyGroupElements(a4, dlog.exponentiate(C2,  eBI));
		
		verified = verified && l1.equals(r1);
		verified = verified && l2.equals(r2);
		verified = verified && l3.equals(r3);
		verified = verified && l4.equals(r4);
		
		e = null; //Delete the random value e.
		
		//Return true if all checks returned true; false, otherwise.
		return verified;
	}

}
