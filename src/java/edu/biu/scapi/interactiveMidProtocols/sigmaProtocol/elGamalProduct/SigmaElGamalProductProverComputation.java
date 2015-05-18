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

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

public class SigmaElGamalProductProverComputation implements SigmaProverComputation, DlogBasedSigma{
	private DlogGroup dlog;			//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	private int t;
	private SecureRandom random;
	private BigInteger qMinusOne;
	
	private SigmaElGamalProductProverInput inp;
	private BigInteger u1, u2, u3;
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaElGamalProductProverComputation(DlogGroup dlog, int t, SecureRandom random) {
		this.dlog = dlog;
		this.t = t;
		this.random = random;
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
	}
	
	public SigmaElGamalProductProverComputation(DlogGroup dlog2,
			SecureRandom random2) {
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		
		this.dlog = dlog2;
		this.t = Integer.parseInt(statisticalParameter);
		this.random = random2;
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
	}

	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		//Delegates the computation to the underlying Sigma DH prover.
		return t;
	}

	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput in) {
		inp = (SigmaElGamalProductProverInput) in;
		
		u1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		u2 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		u3 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		GroupElement g = dlog.getGenerator(),
				     h = inp.getCommonParams().getPublicKey().getH(),
				     A1 = inp.getCommonParams().getA().getC1(),
				     A2 = inp.getCommonParams().getA().getC2();
		
		GroupElement a1 = dlog.exponentiate(g, u1);
		GroupElement a2 = dlog.multiplyGroupElements(dlog.exponentiate(h, u1), dlog.exponentiate(g, u2)); 
		GroupElement a3 = dlog.multiplyGroupElements(dlog.exponentiate(A1, u2), dlog.exponentiate(g, u3)); 
		GroupElement a4 = dlog.multiplyGroupElements(dlog.exponentiate(A2, u2), dlog.exponentiate(h, u3));
		
		return new SigmaElGamalProductAnnouncement(a1.generateSendableData(),
				                                                 a2.generateSendableData(),
				                                                 a3.generateSendableData(),
				                                                 a4.generateSendableData());
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
	 * Computes the second message of the protocol.
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		//Compute z = (r+ew) mod q
		BigInteger q = dlog.getOrder();
		BigInteger e = new BigInteger(1, challenge);
		
		BigInteger er2 = u1.add(e.multiply(inp.getR2())).mod(q);
		BigInteger ex2 = u2.add(e.multiply(inp.getX2())).mod(q);
		BigInteger er3 = u3.add(e.multiply(inp.getR3())).mod(q);
		
		//Delete the random value r
		u1 = BigInteger.ZERO;
		u2 = BigInteger.ZERO;
		u3 = BigInteger.ZERO;
				
		//Create and return SigmaBIMsg with z.
		return new SigmaElGamalProductSecondMsg(er2, ex2, er3);	
		
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaElGamalCommittedValueSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaElGamalProductSimulator(null);
	}

}
