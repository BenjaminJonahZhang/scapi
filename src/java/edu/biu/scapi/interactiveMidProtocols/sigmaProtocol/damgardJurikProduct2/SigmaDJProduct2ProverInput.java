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

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDJProduct2ProverComputation.
 *
 * This protocol is used for a party to prove that 3 ciphertexts c1,c2,c3 are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.
 * The prover knows the plaintext and randomness of the second plaintext, and the randomness used to blind the resulting encryption.<p>
 * 
 * @author Eindhoven University of Technology (Meilof Veeningen)
 *
 */
public class SigmaDJProduct2ProverInput implements SigmaProverInput{
	
	private SigmaDJProduct2CommonInput params;
	private BigIntegerPlainText plainb;
	private BigInteger rb, rab; //randomness used to encrypt.
	
	/**
	 * Sets the given public key, ciphertexts, plaintext and randomness
	 * @param publicKey  Public key of the encryption scheme
	 * @param ciphera    First ciphertext (unknown plaintext)
	 * @param cipherb    Second ciphertext (known plaintext)
	 * @param cipherab   Product ciphertext (known randomisation value)
	 * @param plainb     Plaintext of second ciphertext
	 * @param rb         Randomness of second ciphertext
	 * @param rab        Randomness of re-randomisation of product
	 */
	public SigmaDJProduct2ProverInput(DamgardJurikPublicKey publicKey,
			                             BigIntegerCiphertext ciphera, BigIntegerCiphertext cipherb, BigIntegerCiphertext cipherab,
			                             BigIntegerPlainText plainb, BigInteger rb, BigInteger rab) {
		params = new SigmaDJProduct2CommonInput(publicKey, ciphera, cipherb, cipherab);
		this.plainb = plainb;
		this.rb = rb;
		this.rab = rab;
	}
	
	/**
	 * Get plaintext of second encryption
	 * @return The plaintext
	 */
	public BigIntegerPlainText getPlainB() { return plainb; }
	/**
	 * Get randomness of second encryption
	 * @return The randomness
	 */
	public BigInteger getRB() { return rb; }
	/**
	 * Get randomness for re-randomisation of product
	 * @return The randomness
	 */
	public BigInteger getRAB() { return rab; }

	@Override
	public SigmaDJProduct2CommonInput getCommonParams() {
		return params;
	} 

}
