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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.elGamalCTKnowledge;

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dlog.SigmaDlogProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dlog.SigmaDlogProverInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol prover computation.
 * 
 * This protocol is used for a committer to prove that it knows the value committed to in the commitment (h,c1, c2).
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCTKnowledgeProverComputation implements SigmaProverComputation, DlogBasedSigma{

	/*	
	  This class uses an instance of SigmaDlogProver with:
	  	�	Common parameters (G,q,g) and t
		�	Common input: h (1st element of commitment)
		�	P�s private input: a value w in Zq such that h = g^w (given w can decrypt and so this proves knowledge of committed value).	
	*/	 
	
	private SigmaDlogProverComputation sigmaDlog;	//underlying SigmaDlogProver to use.
	private DlogGroup dlog;				//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaElGamalCTKnowledgeProverComputation(DlogGroup dlog, int t, SecureRandom random) {
		
		//Creates the underlying SigmaDlogProver object with the given parameters.
		sigmaDlog = new SigmaDlogProverComputation(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		//Delegates the computation to the underlying Sigma Dlog prover.
		return sigmaDlog.getSoundnessParam();
	}


	/**
	 * Converts the input for this Sigma protocol to the underlying protocol.
	 * @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
	 */
	private SigmaDlogProverInput convertInput(SigmaProverInput in) {
		if (!(in instanceof SigmaElGamalCTKnowledgeProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalCTKnowledgeProverInput");
		}
		SigmaElGamalCTKnowledgeProverInput input = (SigmaElGamalCTKnowledgeProverInput) in;
		
		//Create an input object to the underlying sigma dlog prover.
		GroupElement h = dlog.reconstructElement(true, input.getCommonParams().getCommitment().getPublicKey().getC());
		return new SigmaDlogProverInput(h, input.getW());
		
	}

	/**
	 * Computes the first message of the protocol.
	 * @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
	 * @return the computed message
	 * @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput in) {
		SigmaDlogProverInput input = convertInput(in);
		
		//Delegates the computation to the underlying Sigma Dlog prover.
		return sigmaDlog.computeFirstMsg(input);
	}

	/**
	 * Computes the second message of the protocol.
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		//Delegates the computation to the underlying Sigma Dlog prover.
		return sigmaDlog.computeSecondMsg(challenge);
		
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaDlogSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaElGamalCTKnowledgeSimulator(sigmaDlog.getSimulator());
	}

}
