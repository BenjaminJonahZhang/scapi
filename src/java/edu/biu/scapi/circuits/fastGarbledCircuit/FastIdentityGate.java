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

package edu.biu.scapi.circuits.fastGarbledCircuit;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.garbledCircuit.BasicGarbledTablesHolder;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.exceptions.TweakNotSetException;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

public class FastIdentityGate {
	private MultiKeyEncryptionScheme mes; 	// The {@code MultiKeyEncryptionScheme} that will be used to garbled and compute this Gate.
	private PseudorandomGenerator prg;		//The prg to use in case of garbling using a seed.
	
	private BasicGarbledTablesHolder garbledTablesHolder; 	//Holds the garbled tables.
	
	//The number of this {@code IdentityGate}. This number is used to order {@code IdentityGate}s in a {@link GarbledBooleanCircuitExtended}
	int gateNumber;
	
	/**
	 * Constructs an identity gate using the given {@code MultiKeyEncryptionScheme}.
	 * This constructor should be used in case the garbling is going to be done using the enryption scheme.
	 * In case of the garbling is going to be done using a prg and seed, use the constructor that accepts a prg.
	 * @param gateNumber The gate's index.
	 * @param mes The encryption scheme used to garble this gate.
	 * @param garbledTablesHolder A reference to the garbled tables of the circuit.
   	 */
	FastIdentityGate(int gateNumber, MultiKeyEncryptionScheme mes, BasicGarbledTablesHolder garbledTablesHolder){
		//Sets the given parameters.
	    this.mes = mes;
		this.gateNumber = gateNumber;
	    this.garbledTablesHolder = garbledTablesHolder;
	}
	
	/**
	 * Constructs an identity gate using the given {@code MultiKeyEncryptionScheme} and {@link PseudorandomGenerator}.
	 * This constructor should be used in case the garbling is going to be done using using a prg and seed.
	 * In case of the garbling is going to be done using the enryption scheme, use the other constructor.
	 * @param gateNumber The gate's index.
	 * @param mes The encryption scheme used to garble this gate.
	 * @param garbledTablesHolder A reference to the garbled tables of the circuit.
	 * @param prg The {@link PseudorandomGenerator} object to use during garbling.
   	 */
	FastIdentityGate(int gateNumber, MultiKeyEncryptionScheme mes, BasicGarbledTablesHolder garbledTablesHolder, PseudorandomGenerator prg){
		this(gateNumber, mes, garbledTablesHolder);
		this.prg = prg;
	}
  
	
	/**
	 * Creates the garbled table of this gate using the given keys.
	 * @param inputKeys Both keys of the input wire.
	 * @param inputKeys Both keys of the output wire.
	 * @param outputsOffset 
	 * @param inputsOffset 
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
	void createGarbledTable(byte[] inputKeys, int inputsOffset, byte[] outputKeys, int outputsOffset) throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
	  
		/*
		 * Identity gate has one input wire and one output wire.
		 * Assume input wire's keys are k0, k1 and output wire's keys k0', k1'.
		 * The garbled table is as follows:
		 * 
		 * Enc(k0')Enc(0^cipherSize) using k0 - row number i (i = 0 ,1)
		 * Enc(k1')Enc(0^cipherSize) using k1 - row number 1-i
		 * 
		 */
		
		//Allocate memory to the garbled table. Two rows when each row contain two encryptions.
		byte[] garbledTable = new byte[2 * mes.getCipherSize() * 2];
		//Set the created table to the holder.
		garbledTablesHolder.toDoubleByteArray()[gateNumber] = garbledTable;
		
		//The order of the rows should be random.
		//In case of garbling using a seed, the random choose is done using the prg.
	  	int position;
	  	if (prg != null){
	  		byte[] out = new byte[1];
	  		prg.getPRGBytes(out, 0, 1);
	  		position = ((out[0] == 0)? 0 : 1);
	  	} else{
	  		position = new SecureRandom().nextBoolean() == true? 1 : 0;
	  		
	  	}
		  	
	  	SecretKey keyToEncryptOn;
	  	byte[] zeros = new byte[mes.getCipherSize()];
	  	
	  	//Tweak is required by some encryption schemes.
	  	ByteBuffer tweak = ByteBuffer.allocate(16);
		tweak.putInt(gateNumber);
		
		byte[] keyPlaintext = new byte[mes.getCipherSize()];
		
		//Set each input key in the encryption scheme, encrypt the corresponding output key and then encrypt zeros.
	  	for(int i=0; i<2; i++){
	  		keyToEncryptOn = new SecretKeySpec(inputKeys, inputsOffset+mes.getCipherSize()*i, mes.getCipherSize(), "");
	  		
	  		// Set the keys and the tweak of the encryption scheme.
		  	mes.setKey(mes.generateMultiKey(keyToEncryptOn));
		  	mes.setTweak(tweak.array());
		  	System.arraycopy(outputKeys, outputsOffset+mes.getCipherSize()*i, keyPlaintext, 0, mes.getCipherSize());
		  	
		  	// Encrypt the output key and zeros and put the ciphertexts in the garbled table.
		  	try {
				System.arraycopy(mes.encrypt(keyPlaintext), 0, garbledTable, position*mes.getCipherSize()*2, mes.getCipherSize());
				System.arraycopy(mes.encrypt(zeros), 0, garbledTable, position*mes.getCipherSize()*2 + mes.getCipherSize(), mes.getCipherSize());
				
			} catch (KeyNotSetException e) {
				// Should not occur since the encryption has a key.
			} catch (TweakNotSetException e) {
				// Should not occur since the encryption has a tweak.			
			}
		  	//flip row for next round.
		  	position = 1-position;
	  	}	  	
	}
	
	/**
	 * Computes the output of this gate and sets the output wire to that value.
	 * @param garbledInput contain the input garbled input key.
	 * @param computedWires	Should be filled with the output of the gate.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws CiphertextTooLongException
	 */
	public void compute(byte[] garbledInput, byte[] computedWires) throws InvalidKeyException, IllegalBlockSizeException,
			CiphertextTooLongException {
		/*
		 * Identity gate has one input wire and one output wire.
		 * Assume input wire's keys are k0, k1 and output wire's keys k0', k1'.
		 * 
		 * The garbled table is as follows:
		 * 
		 * Enc(k0')Enc(0^cipherSize) using k0 - row number i (i = 0 ,1)
		 * Enc(k1')Enc(0^cipherSize) using k1 - row number 1-i
		 * 
		 * When computing, the input wire contains one of k0 or k1.
		 * We need to find which row to decrypt.
		 * The algorithm:
		 * 
		 * 1. Decrypt part two of the first row, 
		 * 2. If the result is 0^cipherSize, decrypt the first part of the first row. This is the output wire of the gate.
		 * 3. Else, decrypt part two of the second row, if the result is 0^cipherSize, decrypt the first part of the second row. This is the output wire of the gate.
		 * 4. Else, throw exception.
		 */
		
		//Get the input garbled value.
		SecretKey keyToDecryptOn = new SecretKeySpec(garbledInput, gateNumber*mes.getCipherSize(), mes.getCipherSize(), "");
		  
		//Set the key and tweak to the encryption scheme.
		mes.setKey(mes.generateMultiKey(keyToDecryptOn));
		ByteBuffer tweak = ByteBuffer.allocate(16);
		tweak.putInt(gateNumber);
		mes.setTweak(tweak.array());
		
		byte[] wireValue = null;
		
		try {
			// Find which row has the encryption of zeros using the given key. 
			int rowI = -1;
			for (int i=0; i<2 && rowI<0; i++){
				//Decrypt the zeros part.
				byte[] validateZeros = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
					i*mes.getCipherSize()*2 + mes.getCipherSize(), i*mes.getCipherSize()*2 + 2*mes.getCipherSize()));
				//Check if the result are zeros.
				boolean validateRow = validateRow(validateZeros);
				//In case of zeros, fix the row index.
				if (validateRow){
					rowI = i;
				}
			}
			
			//If both rows do not contain encryption of zeros according the given key, throw exception.
			if (rowI == -1){
				throw new IllegalArgumentException("input wire value is invalid");	
			}
			
			//Decrypt the first part of the chosen row.
			wireValue = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
							rowI*mes.getCipherSize()*2, rowI*mes.getCipherSize()*2+mes.getCipherSize()));
				
		} catch (KeyNotSetException e) {
			// Should not occur since the key was set.
		} catch (TweakNotSetException e) {
			// Should not occur since the tweak was set.
		}
		
		
		// Create the output wire with the decrypted value.
		System.arraycopy(wireValue, 0, computedWires, gateNumber*mes.getCipherSize(), mes.getCipherSize());
	}

	/**
	 * Check that the given byte array contains 0^cipherSize.
	 * @param validateZeros That should be verified.
	 * @return true if the given byte array contains 0^cipherSize; False, otherwise.
	 */
	private boolean validateRow(byte[] validateZeros) {
		boolean validateRow = true;
		//Check that th elength is correct.
		if (validateZeros.length != mes.getCipherSize()){
			validateRow = false;
		}else{
			//Check that each byte is zero.
			for (int i=0; i<mes.getCipherSize(); i++){
				if (validateZeros[i] != 0)
					validateRow = false;
			}
		}
		return validateRow;
	}

	public boolean verify(int gateNumber, byte[] inputKeys, byte[] outputKeys) throws InvalidKeyException, IllegalBlockSizeException,
			CiphertextTooLongException {
		/*
		 *  Step 1: Test to see that these gate's are numbered with the same number. if they're not, then for our purposes they are not
		 * identical. The reason that we treat this as unequal is since in a larger circuit corresponding gates must be identically numbered in 
		 * order for the circuits to be the same.
		 */
		if (this.gateNumber != gateNumber) {
			return false;
		}
		
		/*
		 * Step 3: The decrypted values of the truth table should be(at most) 2 distinct keys--i.e. a 0-encoding for the output wire and a 1-encoding for
		 * the output wire. So, we test that each input key can translate one and only one row in the garbled table. 
		 * Also, check that the row that k0 and k1 decrypt are distinct. 
		 */
		return verifyGarbledTable(inputKeys, outputKeys);
	}
	
	/**
	 * Verifies the garbled table of the gate.
	 * The decrypted values of the truth table should be(at most) 2 distinct keys--i.e. a 0-encoding for the output wire and a 1-encoding for
	 * the output wire. We test that each input key can translate one and only one row in the garbled table. 
	 * Also, check that the row that k0 and k1 decrypt are distinct.
	 * @param allWireValues A map that contains both keys of all the circuit's wires.
	 * @return true if the garbled table is valid; false, otherwise.
	 * @throws CiphertextTooLongException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 */
	protected boolean verifyGarbledTable(byte[] inputKeys, byte[] outputKeys)
			throws CiphertextTooLongException, InvalidKeyException,	IllegalBlockSizeException {
		
		SecretKey outputZeroValue = null;
		SecretKey outputOneValue = null;
		
		//Set the tweak.
		ByteBuffer tweak = ByteBuffer.allocate(16);
		tweak.putInt(gateNumber);
		mes.setTweak(tweak.array());
		
		
		byte[] validateZeros;
		boolean validateRow;
		int rowI = -1;
		try {
			//Get k0, set it to the encryption scheme.
			SecretKey k0 = new SecretKeySpec(inputKeys, gateNumber*mes.getCipherSize()*2, mes.getCipherSize(), "");
			mes.setKey(mes.generateMultiKey(k0));
			
			//Check that k0 decrypts one and only one row.
			for (int i=0; i<2 && rowI<0; i++){
				//Decrypt part two of the row.
				validateZeros = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
					i*mes.getCipherSize()*2 + mes.getCipherSize(), i*mes.getCipherSize()*2 + 2*mes.getCipherSize()));
				//Check the output.
				validateRow = validateRow(validateZeros);
				//If the output contains zeros, and no row was decrypted yet, save the row index.
				//If the output contains zeros, and there is a row that was decrypted yet, return false. (k0 can decrypt more than one row.)
				if (validateRow == true){
					if (rowI>0){
						return false;
					} else{
						rowI = i;
					}
				}
			}
			//If k0 can not decrypt any row, return false.
			if (rowI == -1){
				return false;
			}
			
			//k0 can decrypt one and only one row, decrypt the first part of that row to get k0'.
			byte[] outputValue = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
							rowI*mes.getCipherSize()*2, rowI*mes.getCipherSize()*2+mes.getCipherSize()));
			outputZeroValue = new SecretKeySpec(outputValue, "");
			
			//Get k1, set it to the encryption scheme.
			SecretKey k1 = new SecretKeySpec(inputKeys, (gateNumber*2+1)*mes.getCipherSize(), mes.getCipherSize(), "");
			mes.setKey(mes.generateMultiKey(k1));
			
			//Flip row.
			rowI = -1;
			//Check that k1 decrypts one and only one row.
			for (int i=0; i<2 && rowI<0; i++){
				//Decrypt part two of the row.
				validateZeros = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
					i*mes.getCipherSize()*2 + mes.getCipherSize(), i*mes.getCipherSize()*2 + 2*mes.getCipherSize()));
				//Check the output.
				validateRow = validateRow(validateZeros);
				//If the output contains zeros, and no row was decrypted yet, save the row index.
				//If the output contains zeros, and there is a row that was decrypted yet, return false. (k1 can decrypt more than one row.)
				if (validateRow == true && rowI<0){
					rowI = i;
				}
			}
			//If k1 can not decrypt any row, return false.
			if (rowI == -1){
				return false;
			}
			//k1 can decrypt one and only one row, decrypt the first part of that row to get k1'.
			outputValue = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
							rowI*mes.getCipherSize()*2, rowI*mes.getCipherSize()*2+mes.getCipherSize()));
				
			outputOneValue = new SecretKeySpec(outputValue, "");
			
		} catch (KeyNotSetException e) {
			// Should not occur since the key was set.
		} catch (TweakNotSetException e) {
			// Should not occur since the tweak was set.
		}
		
		//Put the calculated output values as both values of the output wire.
		System.arraycopy(outputZeroValue.getEncoded(), 0, outputKeys, gateNumber*2*mes.getCipherSize(), mes.getCipherSize());
		System.arraycopy(outputOneValue.getEncoded(), 0, outputKeys, (gateNumber*2+1)*mes.getCipherSize(), mes.getCipherSize());
		
		return true;
	}
}
