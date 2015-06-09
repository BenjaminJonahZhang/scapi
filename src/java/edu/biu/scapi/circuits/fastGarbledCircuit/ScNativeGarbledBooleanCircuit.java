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
import java.security.SecureRandom;

import edu.biu.scapi.circuits.garbledCircuit.GarbledTablesHolder;
import edu.biu.scapi.circuits.garbledCircuit.JustGarbledGarbledTablesHolder;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;



/**
 * A concrete implementation of FastGarbledBooleanCircuit that is a wrapper for a code of SCAPI written in c++y.<p>
 * The circuit can be used as a regular circuit in java and the actual calculations are done in the c++ jni dll
 * calling functions in the Native SCAPI library. In some cases, there is a need to get back information that 
 * is stored in the java class (such as the garbled tables, input keys, etc). This java wrapper gives us
 * the flexibility to work from java, for example with 2 parties and sending information via the java channel. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class ScNativeGarbledBooleanCircuit implements FastGarbledBooleanCircuit{

	
	public static enum CircuitType {
		
		FREE_XOR_HALF_GATES,
		FREE_XOR_ROW_REDUCTION,
		FREE_XOR_STANDARD,
		STANDARD
	}
	
	
	private static final int SCAPI_NATIVE_KEY_SIZE = 16;//The number of bytes in each just garbled key 
	private long garbledCircuitPtr = 0; //Pointer to the native garbledCircuit object
	private int numberOfParties;
	private int[] inputsIndices;
	private int[] outputWireIndices;
	private int[] numOfInputsForEachParty;
	private byte[] garbledInputs;
	private boolean isNonXorOutputsRequired;
	
	private native long createGarbledcircuit(String fileName, int type, boolean isNonXorOutputsRequired);//Creates a garbled. It returns the pointer to that circuit saved in the dll memory 
	private native int[] getOutputIndicesArray(long ptr);//Returns the output indices taken from the circuit file.
	private native int[] getInputIndicesArray(long ptr);//Returns the input indices taken from the circuit file..
	private native int[] getNumOfInputsForEachParty(long ptr);//Returns an array that stores the number of inputs for each party
	private native void setGarbleTables(long ptr, byte[] garbledTable);//Sets the garbled tables. This is a costly function since we need to pass a large amount of information
																	   //from the java memory to the c++ jni memory space
																			
	private native byte[] getGarbleTables(long ptr);//Gets the garbled tables from the jni dll. Again, this is a costly functions since we need to pass a large amount of information
													//from the dll memory space to the java memory space.
	
	
	
	/*
	 * The translation table stores the signal bit for the output wires. Thus, it just tells you whether the wire coming out is a 
	 * 0 or 1 but nothing about the plaintext of the wires is revealed. This is good since it is possible that a circuit output 
	 * wire is also an input wire to a different gate, and thus if the translation table contained the plaintext of both possible
	 * values of the output Wire, the constructing party could change the value of the wire when it is input into a gate, and 
	 * privacy and/or correctness will not be preserved. Therefore, we only reveal the signal bit, and the other
	 * possible value for the wire is not stored on the translation table.
	 */
	private native byte[] getTranslationTable(long ptr);//Gets the translation table from the native code. 
	private native void setTranslationTable(long ptr, byte[]translationTable);//Sets the translation table stored in the native code. 
	
	private native long garble( byte[] inputKeys, byte[] outputKeys, byte[] translationTable, byte[] seed, long ptr);//Does the garbling of the circuit, returns the input keys and the output keys that were generated
																			  //by the circuit. The input and the output keys are converted to the structures that are defined 
																			  //in the SCAPI circuit
	private native byte[] compute(long ptr, byte[] inputKeys);//Does the compute and returns the output keys that are the results.
	private native boolean verify(long ptr, byte[] bothInputKeys);//Does the compute and returns the output keys that are the results.
	private native boolean internalVerify(long ptr, byte[] bothInputKeys, byte[] emptyBothOutputKeys);//does the verify without checking the translation table
	private native byte[] translate(long ptr, byte[] ouyputKeys);
	private native byte[] verifyTranslate(long ptr, byte[] singleoutputKeys, byte []bothOutputKeys);
	private native boolean verifyTranslationTable(long ptr, byte []bothOutputKeys);
	private native void deleteCircuit(long ptr);//Deletes the memory of the circuit in the dll.
	
	
	
	/**
	 * A constructor that passes the file to the native code in order to create a circuit object. The pointer of the 
	 * garbled circuit object is saved in this java class in order to refer to in when calling native functions.
	 * The constructor also initializes information stored in java as well as in the c++ code.
	 * 
	 * @param fileName the name of the circuit file.
	 * @param isFreeXor a flag indicating the use of the optimization of FreeXor
	 * @param isRowReduction a flag indicating the use of the optimization of Row Reduction
	 */
	public ScNativeGarbledBooleanCircuit(String fileName, CircuitType type, boolean isNonXorOutputsRequired){

		this.isNonXorOutputsRequired = isNonXorOutputsRequired;
		
		//create an object in the native code
		garbledCircuitPtr = createGarbledcircuit(fileName, type.ordinal(),isNonXorOutputsRequired);
	
		outputWireIndices =  getOutputIndicesArray(garbledCircuitPtr);//Returns the output indices taken from the circuit file.
		inputsIndices = getInputIndicesArray(garbledCircuitPtr);//Returns the input indices taken from the circuit file..
		
		numOfInputsForEachParty = getNumOfInputsForEachParty(garbledCircuitPtr);
		
	}
	
	
	/**
	 * This method generates all the needed keys of the circuit.  
	 * It then creates the garbled table according to those values.<p>
	 * @return FastCircuitCreationValues Contains both keys for each input and output wire and the translation table.
	 */
	@Override
	public FastCircuitCreationValues garble() {
		 SecureRandom random = new SecureRandom();
		 byte[] seed = new byte[16];
		 random.nextBytes(seed);
		 try {
			return garble(seed);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * This method generates all the needed keys of the circuit.  
	 * It then creates the garbled table according to those values.<p>
	 * @param seed Used as the aes key that generates the wire keys.
	 * @return FastCircuitCreationValues Contains both keys for each input and output wire and the translation table.
	 * @throws InvalidKeyException In case the seed is an invalid key for the given PRG.
	 */
	@Override
	public FastCircuitCreationValues garble(byte[] seed) throws InvalidKeyException {
		if (seed.length != 16){
			throw new InvalidKeyException("seed length should be 16 bytes");
		}
		
		byte[] allInputWireValues = null;
		byte[] allOutputWireValues = null;
		byte[] translationTable = null;
		
		allInputWireValues = new byte[inputsIndices.length*SCAPI_NATIVE_KEY_SIZE*2];
		allOutputWireValues  = new byte[outputWireIndices.length*SCAPI_NATIVE_KEY_SIZE*2];
		translationTable = new byte[outputWireIndices.length];
		
		garble(allInputWireValues, allOutputWireValues, translationTable, seed,garbledCircuitPtr);
		
		FastCircuitCreationValues outputVal = new FastCircuitCreationValues(allInputWireValues, allOutputWireValues, translationTable);
		
		
		return outputVal;
	}
	
	
	/**
	 * This method takes an array containing the <b> non garbled</b> values, both keys for all input wires and the party number which the inputs belong to. <p>
	 * This method then performs the lookup on the allInputWireValues according to the party number and returns the keys 
	 * of the corresponding input bits.
	 * @param ungarbledInputBits An array containing the <b> non garbled</b> value for each input wire of the given party number. 
	 * @param allInputWireValues The array containing both garbled values (keys) for each input wire.
	 * @param partyNumber The number of party which the inputs belong to.
	 * @return an array containing a single key of each input wire of the given party in a single dimension array. The keys
	 *  	   are of the same size which is known in advance.
	 */
	@Override
	public byte[] getGarbledInputFromUngarbledInput(byte[] ungarbledInputBits,
			byte[] allInputWireValues, int partyNumber) {
		
		int startingIndex = 0;
		
		for(int i=0; i<partyNumber-1;i++){
			
			startingIndex+=numOfInputsForEachParty[i];
			
		}
		
		int numberOfInputsForThisParty = numOfInputsForEachParty[partyNumber-1];
		byte[] result = new byte[SCAPI_NATIVE_KEY_SIZE*numberOfInputsForThisParty];
		
		for(int i=0; i<  numberOfInputsForThisParty; i++)
			
			if(ungarbledInputBits[i]==0){
				//Copy the relevant key of the input into the result array.
	  			System.arraycopy(allInputWireValues, (i + startingIndex) * 2 * SCAPI_NATIVE_KEY_SIZE,result , i *SCAPI_NATIVE_KEY_SIZE, SCAPI_NATIVE_KEY_SIZE);
			}
			else{
				//Copy the relevant key of the input into the result array.
	  			System.arraycopy(allInputWireValues, ((i + startingIndex) * 2 +1)*SCAPI_NATIVE_KEY_SIZE,result , i*SCAPI_NATIVE_KEY_SIZE, SCAPI_NATIVE_KEY_SIZE);
			
		}
		
		return result;
		
		
	}
	
	@Override
	public void setInputs(byte[] garbledInputs){
		this.garbledInputs = garbledInputs;
	}
	/**
	 * Computes the circuit using the given inputs. <p>
	 * It returns an array containing the garbled output. This output can be translated via the {@link #translate()} method.
	 * @param garbledInput A single key for each input wire.
	 * @return returns an array containing the garbled value of each output wire.
	 * @throws NotAllInputsSetException if the given inputs array is not the same size of the inputs for this circuit.
	 */
	
	@Override
	public byte[] compute() throws NotAllInputsSetException {
		
		if (garbledInputs.length/16!= inputsIndices.length) {
				throw new NotAllInputsSetException();
			}
		
		byte[] result = compute(garbledCircuitPtr, garbledInputs);
		
		//PATCH should be removed after jni problems are solved.
		//temp.getTime();
		
		return result;
		
		
	}
	
	
	
	/**
     * The verify method is used in the case of malicious adversaries.<p>
     * For example, Alice constructs n circuits and Bob can verify n-1 of them (of his choice) to confirm that they are indeed garbling of the 
     * agreed upon non garbled circuit. In order to verify, Alice has to give Bob both keys for each of the input wires.
     * @param allInputWireValues An array containing both keys for each input wire, the keys for each wire are given one after the other.
     * @return {@code true} if this {@code FastGarbledBooleanCircuit} is a garbling the given keys, {@code false} if it is not.
     */
	@Override
	public boolean verify(byte[] allInputWireValues) {
		
		if(isNonXorOutputsRequired==true){
			throw new IllegalStateException("cannot verify without seed");
		}
		return verify(garbledCircuitPtr, allInputWireValues);
		
	}
	
	/**
     * This function behaves exactly as the verify(byte[] allInputWireValues) method except the last part.
     * The verify function verifies that the translation table matches the resulted output garbled values, while this function does not check it 
     * but return the resulted output garbled values. 
     * @param allInputWireValues An array containing both keys for each input wire.
     * @param allOutputWireValues An array containing both keys for each output wire. 
     * When calling the function this array should be empty and will be filled during the process of the function.
     * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling the given keys, {@code false} if it is not.
     */
	
	@Override
	public boolean internalVerify(byte[] allInputWireValues, byte[] allOutputWireValues) {
		
		if(isNonXorOutputsRequired==true){
			throw new IllegalStateException("cannot verify without seed");
		}
		return internalVerify(garbledCircuitPtr, allInputWireValues, allOutputWireValues);
	}
	
	/**
	 * Translates the garbled output obtained from the {@link #compute()} function into a meaningful(i.e. 0-1) output.<p>
	 * This is done in the native code and gets back the result.
	 * @param garbledOutput An array contains the garbled output. 
	 * @return an array contains the output bit for each output wire.
	 */
	@Override
	public byte[] translate(byte[] garbledOutput) {
		return translate(garbledCircuitPtr,garbledOutput);
	}
	
	/**
	 * Verifies that the given garbledOutput is valid values according to the given all OutputWireValues. <p>
	 * Meaning, for each output wire, checks that the garbled wire is one of the two possibilities.
	 * Then, translates the garbled output obtained from the {@link #compute()} function into a meaningful(i.e. 0-1) output.<p>
	 * @param garbledOutput An array contains the garbled output. 
	 * @param allOutputWireValues both values for each output wire.
	 * @return an array contains the output bit for each output wire.
	 * @throws CheatAttemptException if there is a garbledOutput values that is not one of the two possibilities.
	 */
	@Override
	public byte[] verifiedTranslate(byte[] garbledOutput,
			byte[] allOutputWireValues) throws CheatAttemptException {
		return verifyTranslate(garbledCircuitPtr, garbledOutput, allOutputWireValues);
	}
	
	
	/**
	 * The garbled tables are stored in the native code circuit for all the gates. This method returns the garbled tables. <p>
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and the translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and the translation tables if 
	 * necessary). The advantage is that the size of the tables only is much smaller that all the information stored in the circuit 
	 * (gates and other member variables). The size becomes important when sending large circuits.
	 * 
	 */
	@Override
	public GarbledTablesHolder getGarbledTables() {
		
		GarbledTablesHolder tableHolder;
				
		tableHolder = new JustGarbledGarbledTablesHolder(getGarbleTables(garbledCircuitPtr));
				
		return tableHolder;
	}
	
	/**
	 * Sets the garbled tables of this circuit in the native code where it is actually stored.
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and the translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and the translation tables if necessary).
	 * The advantage is that the size of the tables only is much smaller that all the information stored in the circuit (gates and other 
	 * member variables). The size becomes important when sending large circuits.<p>
	 * The receiver of the circuits will set the garbled tables for the relevant circuit.
	 */
	@Override
	public void setGarbledTables(GarbledTablesHolder garbledTables) {
		setGarbleTables(garbledCircuitPtr, garbledTables.toDoubleByteArray()[0]);
		
	}
	
	/**
     * Returns the translation table of the circuit calculated and stored in the native code. <P>
     * This is necessary since the constructor of the circuit may want to pass the translation table to a different party. <p>
     * Usually, this will be used when the other party (not the constructor of the circuit) creates a circuit, sets the garbled tables 
     * and needs the translation table as well to complete the construction of the circuit.
     * @return the translation table of the circuit.  
     */
	@Override
	public byte[] getTranslationTable() {
		
		return getTranslationTable(garbledCircuitPtr);
	}
	
	/**
	 * Sets the translation table of the circuit stored in the native code. <p>
	 * This is necessary when the garbled tables where set and we would like to compute the circuit later on. 
	 * @param translationTable This value should match the garbled tables of the circuit.
	 */
	@Override
	public void setTranslationTable(byte[] translationTable) {
		
		setTranslationTable(garbledCircuitPtr, translationTable);
		
	}
	
	/**
	 * Returns the input wires' indices of the given party.
	 * We only have the number of inputs for each party and thus we copy the relevant indices from the inputIndices for all the parties.
	 * @param partyNumber The number of the party which we need his input wire indices.
	 * @return an array contains the indices of the input wires of the given party number.
	 * @throws NoSuchPartyException In case the given party number is not valid.
	 */
	@Override
	public int[] getInputWireIndices(int partyNumber)
			throws NoSuchPartyException {
		
		int startingIndex = 0;
		
		for(int i=0; i<partyNumber-1;i++){
			
			startingIndex+=numOfInputsForEachParty[i];
			
		}
		
		int numberOfInputsForThisParty = numOfInputsForEachParty[partyNumber-1];
		int[] result = new int[numberOfInputsForThisParty];
		
			
		//Copy the relevant key of the input into the result array.
  		System.arraycopy(inputsIndices, startingIndex,result ,0, numberOfInputsForThisParty );
		
		return result;
	
	}
	@Override
	public int[] getOutputWireIndices() {
		return outputWireIndices;
	}
	@Override
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException {
		
		return numOfInputsForEachParty[partyNumber-1];
	}
	@Override
	public int getNumberOfParties() {

		return numberOfParties;
	}
	
	
	@Override
	public boolean verifyTranslationTable(byte[] allOutputWireValues) {
		
		return verifyTranslationTable(garbledCircuitPtr, allOutputWireValues);
	}
	@Override
	public int[] getInputWireIndices() {
		return inputsIndices;
	}
	@Override
	public int getKeySize() {
		return SCAPI_NATIVE_KEY_SIZE;
	}

	@Override
	protected void finalize() throws Throwable {
		deleteCircuit(garbledCircuitPtr);
	}
	
	static {
		 
		 //loads the JustGarbledJavaInterface jni dll
		 System.loadLibrary("ScGarbledCircuitJavaInterface");
	}

	
	
}
