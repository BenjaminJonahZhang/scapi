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

import java.io.IOException;
import java.io.ObjectOutputStream;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikProduct2 verifier and simulator.<p>
 * In SigmaProtocolDamgardJurikProduct2, the common input contains DamgardJurikPublicKey and three BigIntegerCiphertexts.
 * 
 * @author Eindhoven University of Technology, Meilof Veeningen
 *
 */
public class SigmaDJProduct2CommonInput implements SigmaCommonInput{
	
	private static final long serialVersionUID = -4073809422503620748L;
	private DamgardJurikPublicKey publicKey;
	private BigIntegerCiphertext ciphera, cipherb, cipherab;
	
	/**
	 * Sets the given public key and ciphertexts.
	 * @param publicKey used to encrypt.
	 * @param ciphera encryption of plaintext a.
	 * @param cipherb encryption of plaintext b.
	 * @param cipherab encryption of plaintext ab.
	 */
	public SigmaDJProduct2CommonInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext ciphera, BigIntegerCiphertext cipherb, BigIntegerCiphertext cipherab){
		this.publicKey = publicKey;
		this.ciphera = ciphera;
		this.cipherb = cipherb;
		this.cipherab = cipherab;
	}
	
	/**
	 * Returns the public key used to encrypt.
	 * @return public key used to encrypt.
	 */
	public DamgardJurikPublicKey getPublicKey(){
		return publicKey;
	}
	
	/**
	 * Returns the first ciphertext (of which prover does not know plaintext)
	 * @return  The first ciphertext
	 */
	public BigIntegerCiphertext getCiphertextA(){ return ciphera; }
	
	/**
	 * Returns the second ciphertext (of which prover knows plaintext)
	 * @return The second ciphertext
	 */
	public BigIntegerCiphertext getCiphertextB(){ return cipherb; }
	
	/**
	 * Returns the third (product) ciphertext
	 * @return The third (product) ciphertext
	 */
	public BigIntegerCiphertext getCiphertextAB(){ return cipherab; }
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
        out.writeObject(publicKey.generateSendableData());  
        out.writeObject(ciphera);
        out.writeObject(cipherb);
        out.writeObject(cipherab);
    } 
}
