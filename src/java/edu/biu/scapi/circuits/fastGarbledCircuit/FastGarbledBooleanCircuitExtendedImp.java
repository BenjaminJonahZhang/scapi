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

import java.security.InvalidKeyException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.garbledCircuit.BasicGarbledTablesHolder;
import edu.biu.scapi.circuits.garbledCircuit.ExtendedGarbledTablesHolder;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledTablesHolder;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;
import edu.biu.scapi.primitives.prg.openSSL.OpenSSLRC4;

/**
 * This class is an implementation of the fast extended garbled boolean circuit.<P>
 * The extensions implemented in this class are:
 * 1. The ability to set the input or/and output garbled values.
 * 2. The ability to sample the garbled values using a given seed.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 * 
 */
public class FastGarbledBooleanCircuitExtendedImp implements FastGarbledBooleanCircuitExtended {

	/*
	 * In order to allow garbling with fixed input or output keys we decided to add an identity gate 
	 * for each input and output wire. The additional gates will be added only if the user actually set 
	 * the garbled values. 
	 * Meaning, if there are 128 input wires and 128 output wires, and the user set their garbled values, 
	 * our GarbledBooleanCircuitExtended will have 256 more gates. 
	 * This way, if the user gave input or output wires' values it does not relevant to the inner GarbledBooleanCircuit. 
	 * It will generate all keys randomly. The identity gates will map the given input/output keys to the generated ones.
	 *
	 */

	private FastGarbledBooleanCircuit gbc; 			// The underlying circuit to use.
	private PseudorandomGenerator prg; 				// The prg to use when garbling using a seed.
	private MultiKeyEncryptionScheme mes; 			// The underlying encryption scheme to use when garbling using an encryption.
	private FastIdentityGate[] inputIdentityGates;  // The array of input gates in case the user set the input
													// garbled values.
	private FastIdentityGate[] outputIdentityGates; // The array of output gates in case the user set the input
													// garbled values.
	private byte[] garbledInputs;

	/*
	 * Holds the garbled tables of this garbled circuit. This is stored in the garbled circuit and also in the gates. 
	 * We keep the garbled tables that way because when sending the circuit to a different party it is sufficient to 
	 * send only the garbled tables and translation table, if needed. The party who receives the tables only needs 
	 * to change the pointer in the holder class to the received tables.
	 * 
	 * We store the garbled tables in a two dimensional array, the first dimension for each gate and the other 
	 * dimension for the encryptions. Each table of each gate is a one dimensional array of bytes rather than an
	 * array of ciphertexts. This is for time/space efficiency reasons: If a single garbled table is an array of 
	 * ciphertext that holds a byte array the space stored by java is big. The main array holds references for each
	 * item (4 bytes). Each array in java has an overhead of 12 bytes. Thus the garbled table with ciphertexts 
	 * has at least (12+4)*number of rows overhead. If we store the array as one dimensional array we only have 12
	 * bytes overhead for the entire table and thus this is the way we store the garbled tables.
	 */
	private ExtendedGarbledTablesHolder garbledTablesHolder;

	// A map that is used during computation to map a {@code GarbledWire}'s
	// index to the computed and set {@code GarbledWire}.
	private byte[] computedWires;

	private int[] inputIndices; 	// Holds the input wires' indices.
	private int[] outputIndices; 				// Holds the output wires' indices.

	private byte[] inputGarbledValues; 	// Holds the input garbled values given from the user.
	private byte[] outputGarbledValues;	// Holds the output garbled values given from the user.

	// We save the output from the inner circuit because we use it in the translate function:
	// Translate function uses the signal bit format in order to translate, but in case the user 
	// set the output garbled values, the values not necessarily are in that format. 
	// Because the output from the compute function (that will be sent to the translate function)
	// will be the values from the user, we save the output from the inner
	// circuit and use them in order to get the signal bit and do the translate.
	private byte[] outputFromInnerCircuit;

	/**
	 * This constructor should be used in case the garbling is done using a MultiKeyEncryptionScheme. <P>
	 * It gets the inner garbled boolean circuit and the encryption scheme.
	 * 
	 * @param gbc The inner garbled boolean circuit to wrap.
	 * @param mes The MultiKeyEncryptionScheme to use during garbling.
	 */
	public FastGarbledBooleanCircuitExtendedImp(FastGarbledBooleanCircuit gbc, MultiKeyEncryptionScheme mes) {

		this.gbc = gbc;
		this.mes = mes;
		this.prg = new OpenSSLRC4();

		// Input and output indices will be needed multiple times, we hold them as class members to avoid the 
		// creation of the arrays each time they needed.
		outputIndices = gbc.getOutputWireIndices();
		inputIndices = gbc.getInputWireIndices();

		// Create the garbled tables holder with holders for the identity gates
		// and the inner circuit.
		BasicGarbledTablesHolder inputGarbledTables = new BasicGarbledTablesHolder(null);
		BasicGarbledTablesHolder outputGarbledTables = new BasicGarbledTablesHolder(null);
		garbledTablesHolder = new ExtendedGarbledTablesHolder(inputGarbledTables, outputGarbledTables, null);
				
	}

	/**
	 * This constructor should be used in case the garbling is done using a PRG and seed. <P>
	 * It gets the inner garbled boolean circuit, the encryption scheme and the PRG.
	 * 
	 * @param gbc The inner {@link GarbledBooleanCircuit} to wrap.
	 * @param mes The {@link MultiKeyEncryptionScheme} to use during garbling.
	 * @param prg The {@link PseudorandomGenerator} to use during the garbling process.
	 */
	public FastGarbledBooleanCircuitExtendedImp(FastGarbledBooleanCircuit gbc,
			MultiKeyEncryptionScheme mes, PseudorandomGenerator prg) {

		this(gbc, mes);
		this.prg = prg;
	}

	@Override
	public void setInputKeys(byte[] inputValues) {
		this.inputGarbledValues = inputValues;
		
		// Set an empty garbled tables array in the right size.
		garbledTablesHolder.getInputGarbledTables().setGarbledTables(new byte[inputIndices.length][]);
					
		createInputIdentityGates();
	}

	@Override
	public void setOutputKeys(byte[] outputValues) {
		this.outputGarbledValues = outputValues;
		// Set an empty garbled tables array in the right size.
		garbledTablesHolder.getOutputGarbledTables().setGarbledTables(new byte[outputIndices.length][]);
		
		createOutputIdentityGates();
	}

	@Override
	public FastCircuitCreationValues garble() {
		// Call the inner circuit's garble function to generate its keys.
		FastCircuitCreationValues values = gbc.garble();
		// Generate the input and output gates, if needed.
		return generateInputOutputGates(values);
	}

	@Override
	public FastCircuitCreationValues garble(byte[] seed) throws InvalidKeyException {
		// In order to garble using seed, we need two seeds: one for the inner
		// circuit and one for the extended.
		// Use the given seed in order to generate two new seeds.

		// Set the given seed as the prg's key.
		prg.setKey(new SecretKeySpec(seed, ""));

		// use the prg to generate two seeds.
		byte[] out = new byte[seed.length * 2];
		prg.getPRGBytes(out, 0, out.length);

		// Create new seeds.
		byte[] innerSeed = new byte[seed.length];
		byte[] extendedSeed = new byte[seed.length];
		System.arraycopy(out, 0, innerSeed, 0, seed.length);
		System.arraycopy(out, seed.length, extendedSeed, 0, seed.length);

		// Garble the inner circuit using the inner seed.
		FastCircuitCreationValues values = gbc.garble(innerSeed);

		// Set the extended seed as the prg's key. It will be used in the
		// identity gates.
		prg.setKey(new SecretKeySpec(extendedSeed, ""));
		// Generate the input and output gates, if needed.
		return generateInputOutputGates(values);
	}

	/**
	 * In case the user set input and/or output keys, create the corresponding gates. <P>
	 * 
	 * @param values The values returned from the inner circuit's garble function.
	 * @return The input and output keys of this circuit, along with the translation table of the inner circuit.
	 */
	private FastCircuitCreationValues generateInputOutputGates(FastCircuitCreationValues values) {
				
		//garbledTablesHolder.setInnerGarbledTables(gbc.getGarbledTables());
		// In case the user set the input keys, create the input identity gates.
		if (inputGarbledValues == null) {
			
			inputGarbledValues = values.getAllInputWireValues();
		}

		// In case the user set the output keys, create the output identity
		// gates.
		if (outputGarbledValues == null) {
			outputGarbledValues = values.getAllOutputWireValues();
		}

		// After we have all keys, create the garbledTables according to them.
		try {
			createGarbledTables(values);
		} catch (InvalidKeyException e) {
			// Should not occur since the keys were generated through the
			// encryption scheme that generates keys that match it.
		} catch (IllegalBlockSizeException e) {
			// Should not occur since the keys were generated through the
			// encryption scheme that generates keys that match it.
		} catch (PlaintextTooLongException e) {
			// Should not occur since the keys were generated through the
			// encryption scheme that generates keys that match it.
		}

		// Return the input and output keys of this circuit, along with the
		// translation table of the inner circuit.
		return new FastCircuitCreationValues(inputGarbledValues, outputGarbledValues, values.getTranslationTable());
	}

	/**
	 * Creates the garbled tables of the identity gates.
	 * 
	 * @param values The input and output keys of the inner garbled circuit.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
	protected void createGarbledTables(FastCircuitCreationValues values) throws InvalidKeyException, IllegalBlockSizeException,
			PlaintextTooLongException {
		int inputGatesSize = inputIndices.length;
		int outputGatesSize = outputIndices.length;
		int identityKeySize = mes.getCipherSize();
		int innerKeySize = gbc.getKeySize();
		// After we have all keys, create the garbledTables according to them.
		if (inputIdentityGates != null) {
			// Each identity gate needs four keys in order to create the garbled table; 
			// Two keys of the input wire and two keys of the output wire. 
			// We get the input keys from the input keys given from the user and the output keys from the 
			// garble function of the inner circuit. 
			// Finally, we call the createGarbledTable function of the identity gate and it creates the garbled table.
			//byte[] inputKeys = new byte[2*identityKeySize];
		//	byte[] outputKeys = new byte[2*innerKeySize];
			// Create garbled tables for each input identity gate.
			for (int i=0; i<inputGatesSize; i++){
			//	System.arraycopy(inputGarbledValues, identityKeySize*2*i, inputKeys, 0, identityKeySize*2);
			//	System.arraycopy(values.getAllInputWireValues(), innerKeySize*2*i, outputKeys, 0, innerKeySize*2);
				inputIdentityGates[i].createGarbledTable(inputGarbledValues, identityKeySize*2*i, values.getAllInputWireValues(), innerKeySize*2*i);
			}
		}

		if (outputIdentityGates != null) {
			// Each identity gate needs four keys in order to create the garbled table; 
			// Two keys of the input wire and two keys of the output wire. 
			// We get the output keys from the output keys given from the user and the input keys from the 
			// garble function of the inner circuit. 
			// Finally, we call the createGarbledTable function of the identity gate and it creates the garbled table.
		//	byte[] inputKeys = new byte[2*innerKeySize];
		//	byte[] outputKeys = new byte[2*identityKeySize];
			// Create garbled tables for each input identity gate.
			for (int i=0; i<outputGatesSize; i++){
				//System.arraycopy(values.getAllOutputWireValues(), innerKeySize*2*i, inputKeys, 0, innerKeySize*2);
			//System.arraycopy(outputGarbledValues, identityKeySize*2*i, outputKeys, 0, identityKeySize*2);
				outputIdentityGates[i].createGarbledTable(values.getAllOutputWireValues(), innerKeySize*2*i, outputGarbledValues, identityKeySize*2*i);
			}
		}
	}

	@Override
	public byte[] getGarbledInputFromUngarbledInput(byte[] ungarbledInputBits, byte[] allInputWireValues, int partyNumber) {

		return gbc.getGarbledInputFromUngarbledInput(ungarbledInputBits, allInputWireValues, partyNumber);
	}

	public void setInputs(byte[] garbledInputs){
		this.garbledInputs = garbledInputs;
	}
	@Override
	public byte[] compute() throws NotAllInputsSetException {
		
		int inputGatesSize = inputIndices.length;
		int identityKeySize = mes.getCipherSize();
		int innerKeySize = gbc.getKeySize();

		// If there are input identity gates, compute each one of them.
		if (inputIdentityGates != null) {
			if (garbledInputs.length != identityKeySize*inputGatesSize){
				throw new NotAllInputsSetException();
			}
			
			computedWires = new byte[inputGatesSize*innerKeySize];
			
			for (FastIdentityGate g : inputIdentityGates){
				try {
					g.compute(garbledInputs, computedWires);
				} catch (InvalidKeyException e) {
					// Should not occur since the keys were generated through
					// the encryption scheme that generates keys that match it.
				} catch (IllegalBlockSizeException e) {
					// Should not occur since the keys were generated through
					// the encryption scheme that generates keys that match it.
				} catch (CiphertextTooLongException e) {
					// Should not occur since the keys were generated through
					// the encryption scheme that generates keys that match it.
				}
			}
		} else{
			if (garbledInputs.length != innerKeySize*inputGatesSize){
				throw new NotAllInputsSetException();
			}
			computedWires = garbledInputs;
		}
		// Compute the inner circuit.
		gbc.setInputs(computedWires);
		outputFromInnerCircuit = gbc.compute();
		byte[] garbledOutputs;
		// If there are output identity gates, compute each one of them.
		if (outputIdentityGates != null) {
			garbledOutputs = new byte[outputIndices.length*identityKeySize];
			
			
			for (FastIdentityGate g : outputIdentityGates) {
				try {
					g.compute(outputFromInnerCircuit, garbledOutputs);
				} catch (InvalidKeyException e) {
					// Should not occur since the keys were generated through
					// the encryption scheme that generates keys that match it.
				} catch (IllegalBlockSizeException e) {
					// Should not occur since the keys were generated through
					// the encryption scheme that generates keys that match it.
				} catch (CiphertextTooLongException e) {
					// Should not occur since the keys were generated through
					// the encryption scheme that generates keys that match it.
				}
			}
		} else{
			garbledOutputs = outputFromInnerCircuit;
		}

		return garbledOutputs;
		
	}

	@Override
	public boolean verify(byte[] allInputWireValues) {

		byte[] internalOutputs = new byte[outputIndices.length*gbc.getKeySize()*2];
		byte[] extendedOutputs = new byte[outputIndices.length*mes.getCipherSize()*2];

		// Call a function that verifies the circuit without verifying the translation table.
		// The function fills the internal and extended output maps.
		boolean verified = verifyCircuitReturnOutputs(allInputWireValues, internalOutputs, extendedOutputs);
		if (verified == false) {
			return false;
		}

		// Verify the translation table using the output from the inner circuit.
		return gbc.verifyTranslationTable(internalOutputs);
	}

	@Override
	public boolean verify(byte[] allInputWireValues, byte[] allOutputWireValues) {

		byte[] internalOutputs = new byte[outputIndices.length*gbc.getKeySize()*2];
		byte[] extendedOutputs = new byte[outputIndices.length*mes.getCipherSize()*2];

		// Call a function that verifies the circuit without verifying the translation table.
		// The function fills the internal and extended output maps.
		boolean verified = verifyCircuitReturnOutputs(allInputWireValues, internalOutputs, extendedOutputs);

		// Verify the translation table using the output from the inner circuit.
		verified = verified && gbc.verifyTranslationTable(internalOutputs);

		// Verify the generated output values with the given output values.
		if (outputIdentityGates != null) {
			verified = verified	&& checkEquality(extendedOutputs, allOutputWireValues);
		}
		return verified;
	}

	@Override
	public boolean internalVerify(byte[] allInputWireValues, byte[] allOutputWireValues) {

		byte[] internalOutputs = new byte[outputIndices.length*gbc.getKeySize()*2];
		byte[] extendedOutputs = new byte[outputIndices.length*mes.getCipherSize()*2];
		
		// Call a function that verifies the circuit without verifying the translation table.
		// The function fills the internal and extended output maps.
		boolean verified = verifyCircuitReturnOutputs(allInputWireValues, internalOutputs, extendedOutputs);

		// This function should return the output keys of the circuit.
		// In case the circuit does not contain output identity gates, the
		// output keys are the same as the output from the inner circuit.
		if (outputIdentityGates == null) {
			allOutputWireValues = internalOutputs;
			// In case the circuit does contain output identity gates, the
			// output keys are the output of the extended circuit.
		} else {
			allOutputWireValues = extendedOutputs;
		}

		return verified;
	}

	/**
	 * Check that the output wires translate correctly.
	 * 
	 * @param keys contains both possible values for every output wire of the inner circuit.
	 * @return true is the output keys are valid. false, otherwise.
	 */
	public boolean verifyTranslationTable(byte[] keys) {
		// Check that the output wires translate correctly.
		// keys contains both possible values for every output wire of the inner circuit.
		// We check the output wire values and make sure that the 0-wire
		// translates to a 0 and that the 1 wire translates to a 1.
		return gbc.verifyTranslationTable(keys);
	}

	/**
	 * Verifies that this circuit is the garbling of the given input garbled values.<P> 
	 * During the execution, fill the given internalOutputs array with the outputs garbled values of the 
	 * internal circuit, and the extendedOutputs array with the outputs garbled values of the extended circuit.
	 * 
	 * @param allInputWireValues  An array containing both keys for each input wire.
	 * @param internalOutputs An empty array that will be filled with the output garbled values of the internal circuit.
	 * @param extendedOutputs An empty array that will be filled with the output garbled values of the extended circuit.
	 * @return true if the circuit is verified; False, otherwise.
	 */
	private boolean verifyCircuitReturnOutputs(byte[] allInputWireValues, byte[] internalOutputs, byte[] extendedOutputs) {
		byte[] internalInputs = new byte[gbc.getKeySize()*inputIndices.length*2]; 
		
		// Verify the input identity gates.
		if (inputIdentityGates != null){
			if (!verifyInputs(allInputWireValues, internalInputs)) {
				return false;
			}
		} else{
			internalInputs = allInputWireValues;
		}

		// Verify the inner circuit without the translation table.
		if (!(gbc.internalVerify(internalInputs, internalOutputs))) {
			return false;
		}
		
		// Verify the output identity gates.
		if (outputIdentityGates != null){
			if (!verifyOutputs(internalOutputs, extendedOutputs)) {
				return false;
			}
		}

		return true;
	}

	@Override
	public boolean verify(byte[] seed, byte[] allInputGarbledValues, byte[] allOutputGarbledValues, CryptographicHash hash, byte[] hashedCircuit)
			throws InvalidKeyException {

		// Verify using a seed verifies that if you create a circuit using the given seed, the output garbled tables 
		// and translation table is correct.
		// This is done by computing a hash function on the garbled tables and translation table and comparing it to 
		// the given hashedCircuit.
		// In case this circuit has no garbled tables yet, garble it to create the tables.
		if (garbledTablesHolder.getInternalGarbledTables().toDoubleByteArray() == null) {
			// Set the input keys if there are.
			if (allInputGarbledValues != null) {
				setInputKeys(allInputGarbledValues);
			}
			// Set the output keys if there are.
			if (allOutputGarbledValues != null) {
				setOutputKeys(allOutputGarbledValues);
			}
			// Garble the circuit using the seed.
			garble(seed);
		}

		// After there are garbled tables and translation table, we need to
		// verify that they are the same as the given one.
		return verifyHashedCircuit(hash, hashedCircuit);
	}

	/**
	 * Checks that the given secretKey arrays contain the same keys.
	 * 
	 * @param secretKeys The first array to compare.
	 * @param secretKeys2 The second array to compare.
	 * @return true if the given arrays are the same; False, otherwise.
	 */
	private boolean checkEquality(byte[] secretKeys, byte[] secretKeys2) {
		if (secretKeys.length != secretKeys2.length) {
			return false;
		}

		for (int i = 0; i < secretKeys.length; i++) {
			if (secretKeys[i] != secretKeys2[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Verifies the output identity gates.
	 * 
	 * @param allWireValues contains both keys for each wire needed by the output gates.
	 * @return true if the output identity gates are verified; False, otherwise.
	 */
	private boolean verifyOutputs(byte[] internalOutputs, byte[] extendedOutputs) {
		int outputNumber = outputIndices.length;

		// Check that the number of output identity gates is the same as the
		// number of output wires.
		if (outputIdentityGates.length != outputNumber) {
			return false;
		}

		// Verify each identity gate. This is done by creating a Gate object
		// with the identity truth table and the right wires indices.
		// The verify method of the identity gate check the gate is consistent
		// with the given created gate.
		for (int i = 0; i < outputNumber; i++) {
			try {
				if (outputIdentityGates[i].verify(i, internalOutputs, extendedOutputs) == false) {
					return false;
				}
			} catch (InvalidKeyException e) {
				// Should not occur since the keys were generated through the
				// encryption scheme that generates keys that match it.
			} catch (IllegalBlockSizeException e) {
				// Should not occur since the keys were generated through the
				// encryption scheme that generates keys that match it.
			} catch (CiphertextTooLongException e) {
				// Should not occur since the keys were generated through the
				// encryption scheme that generates keys that match it.
			}
		}
		return true;
	}

	/**
	 * Verifies the input identity gates.
	 * 
	 * @param allWireValues
	 *            contains both keys for each wire needed by the input gates.
	 * @return true if the input identity gates are verified; False, otherwise.
	 */
	protected boolean verifyInputs(byte[] allInputWireValues, byte[] internalInputs) {

		int inputNumber = inputIndices.length;

		// Check that the number of output identity gates is the same as the
		// number of output wires.
		if (inputIdentityGates.length != inputNumber) {
			return false;
		}

		// Verify each identity gate. This is done by creating a Gate object
		// with the identity truth table and the right wires indices.
		// The verify method of the identity gate check the gate is consistent
		// with the given created gate.
		for (int i = 0; i < inputNumber; i++) {
			try {
				if (inputIdentityGates[i].verify(i, allInputWireValues, internalInputs) == false) {
					return false;
				}
			} catch (InvalidKeyException e) {
				// Should not occur since the keys were generated through the
				// encryption scheme that generates keys that match it.
			} catch (IllegalBlockSizeException e) {
				// Should not occur since the keys were generated through the
				// encryption scheme that generates keys that match it.
			} catch (CiphertextTooLongException e) {
				// Should not occur since the keys were generated through the
				// encryption scheme that generates keys that match it.
			}
		}
		return true;
	}

	@Override
	public byte[] getHashedCircuit(CryptographicHash hash) {
		// Get the garbled tables arrays
		garbledTablesHolder.setInnerGarbledTables(gbc.getGarbledTables());
		byte[][] tables = garbledTablesHolder.toDoubleByteArray();
		int size = tables.length;
		// Update the hash with each gate's garbled table.
		for (int i = 0; i < size; i++) {
			if (tables[i] != null) {
				hash.update(tables[i], 0, tables[i].length);
			}
		}
		size = getOutputWireIndices().length;
		Byte signalbit;
		byte[] signalBitArray;
		// Update the hash with each signal bit.
		for (int i=0; i<size; i++) {
			signalbit = gbc.getTranslationTable()[i];
			signalBitArray = new byte[1];
			signalBitArray[0] = signalbit;
			hash.update(signalBitArray, 0, 1);

		}

		// Compute the hash function.
		byte[] output = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(output, 0);

		return output;
	}

	@Override
	public boolean verifyHashedCircuit(CryptographicHash hash,
			byte[] hashedCircuit) {
		// Get the result of the hash function on the exist garbled tables and
		// translation table.
		byte[] hashedTables = getHashedCircuit(hash);

		// Verify the lengths of both hash results.
		int size = hashedCircuit.length;
		if (size != hashedTables.length) {
			return false;
		}

		// Verify the content of both hash results.
		for (int i = 0; i < size; i++) {
			if (hashedCircuit[i] != hashedTables[i]) {
				return false;
			}
		}

		return true;
	}

	@Override
	public byte[] translate(byte[] garbledOutput) {
		// The translation is done using the translation table that uses the signal bit approach.
		// In case of extended circuit, there is a situation where the last keys were given by the user and 
		// thus they are not necessarily complied to the signal bit approach.
		// For that reason, we save the output of the inner circuit and use it in order to translate.
		// The output will be the same because the added output gates are the identity gates.
		return gbc.translate(outputFromInnerCircuit);

	}

	@Override
	public int[] getInputWireIndices(int partyNumber)
			throws NoSuchPartyException {

		return gbc.getInputWireIndices(partyNumber);
	}

	@Override
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException {

		return gbc.getNumberOfInputs(partyNumber);
	}

	@Override
	public GarbledTablesHolder getGarbledTables() {
		garbledTablesHolder.setInnerGarbledTables(gbc.getGarbledTables());
		return garbledTablesHolder;
	}

	@Override
	public void setGarbledTables(GarbledTablesHolder garbledTables) {
		if (!(garbledTables instanceof ExtendedGarbledTablesHolder)) {
			throw new IllegalArgumentException("garbledTables should be an instance of ExtendedGarbledTablesHolder");
		}

		ExtendedGarbledTablesHolder holder = (ExtendedGarbledTablesHolder) garbledTables;

		this.garbledTablesHolder.setGarbledTables(holder.getInternalGarbledTables(), holder.getInputGarbledTables(),
						holder.getOutputGarbledTables());
		generateInputOutputGates();
		gbc.setGarbledTables(holder.getInternalGarbledTables());
	}

	/**
	 * In case the user set input and/or output keys, create the corresponding gates.<p>
	 * @param values The values returned from the inner circuit's garble function.
	 * @return The input and output keys of this circuit, along with the translation table of the inner circuit.
	 */
	private void generateInputOutputGates() {

		// In case the user set the input keys, create the input identity gates.
		if (garbledTablesHolder.getInputGarbledTables().toDoubleByteArray() != null) {

			createInputIdentityGates();
		}

		// In case the user set the output keys, create the output identity gates.
		if (garbledTablesHolder.getOutputGarbledTables().toDoubleByteArray() != null) {

			createOutputIdentityGates();
		}
	}

	private void createOutputIdentityGates() {
		int size = outputIndices.length;
		// Create an identity gates array in the right size.
		outputIdentityGates = new FastIdentityGate[size];
		
		// Create each output identity gate.
		for (int i = 0; i < size; i++) {
			if (prg == null) {
				outputIdentityGates[i] = new FastIdentityGate(i, mes, garbledTablesHolder.getOutputGarbledTables());
			} else {
				outputIdentityGates[i] = new FastIdentityGate(i, mes, garbledTablesHolder.getOutputGarbledTables(), prg);
			}
		}
	}

	private void createInputIdentityGates() {
		int size = inputIndices.length;
		// Create an identity gates array in the right size.
		inputIdentityGates = new FastIdentityGate[size];
		// Create each input identity gate.
		for (int i = 0; i < size; i++) {
			if (prg == null) {
				inputIdentityGates[i] = new FastIdentityGate(i, mes, garbledTablesHolder.getInputGarbledTables());
			} else {
				inputIdentityGates[i] = new FastIdentityGate(i, mes, garbledTablesHolder.getInputGarbledTables(), prg);
			}
		}
	}

	@Override
	public int[] getOutputWireIndices() {
		return gbc.getOutputWireIndices();
	}

	@Override
	public int getNumberOfParties() {

		return gbc.getNumberOfParties();
	}

	@Override
	public byte[] verifiedTranslate(byte[] garbledOutput, byte[] allOutputWireValues) throws CheatAttemptException {
		
		int[] outputWireIndices = getOutputWireIndices();
		int size = outputWireIndices.length;
		
		// For each wire check that the given output is one of two given possibilities.
		for (int i=0; i<size; i++){
			//Compare the output to both keys. If the output is different from both keys, throw exception.
			if (!(checkEquality(garbledOutput, i*mes.getCipherSize(), allOutputWireValues, i*mes.getCipherSize()*2, mes.getCipherSize())) 
					&& !(checkEquality(garbledOutput, i*mes.getCipherSize(), allOutputWireValues, (i*2+1)*mes.getCipherSize(), mes.getCipherSize()))){
				throw new CheatAttemptException("The given output value is not one of the two given possible values");
			}
		}

		// After verified, the output can be translated.
		return translate(garbledOutput);

	}

	private boolean checkEquality(byte[] output, int resultIndex, byte[] allOutputWireValues, int index, int len) {
		for (int i = 0; i < len; i++) {
			if (output[resultIndex+i] != allOutputWireValues[index +i]) {
				return false;
			}
		}
		return true;
	}

	@Override
	public byte[] getTranslationTable() {

		return gbc.getTranslationTable();
	}

	@Override
	public void setTranslationTable(byte[] translationTable) {
		gbc.setTranslationTable(translationTable);

	}

	@Override
	public int[] getInputWireIndices() {
		return gbc.getInputWireIndices();
	}

	@Override
	public int getKeySize() {
		throw new IllegalStateException("Extended circuit has two types of keys.");
	}
}
