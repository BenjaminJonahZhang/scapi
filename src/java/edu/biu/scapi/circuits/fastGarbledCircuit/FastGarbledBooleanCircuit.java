package edu.biu.scapi.circuits.fastGarbledCircuit;

import java.security.InvalidKeyException;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledTablesHolder;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;

/**
 * {@code FastGarbledBooleanCircuit} is a general interface for all basic garbled circuits. 
 * Fast garbled boolean circuit includes the same functionality as the regular garbled boolean circuit 
 * but it does it faster due to simpler data structures that does not need any conversion to the native code.<p>
 
 * As the garbledBooleanCircuit interface, fast garbled circuits have four main operations: <p>
 * 1. The {@link #garble()} function that generates the keys and creates the garbled tables. <p>
 * 2. The {@link #compute()} function computes a result on a garbled circuit whose input has been set. <p>
 * 3. The {@link #verify(byte[])} method is used in the case of a malicious adversary to verify that the garbled circuit 
 * created is an honest garbling of the agreed upon non garbled circuit. For example, the constructing party constructs many garbled circuits and
 * the second party chooses all but one of them to verify and test the honesty of the constructing party.<p>
 * 4. The {@link #translate(byte[])} that translates the garbled output from {@link #compute()} into meaningful output.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 * 
 */
public interface FastGarbledBooleanCircuit {
		
	/**
	 * This method generates both keys for each wire. Then, creates the garbled table according to those values.<p>
	 * @return FastCircuitCreationValues contains both keys for each input and output wire and the translation table.
	 */
	public FastCircuitCreationValues garble();
	
	/**
	 * This method generates both keys for each input wire using the seed. 
	 * It then creates the garbled table according to those values.<p>
	 * @param seed Used to initialize the prg.
	 * @return FastCircuitCreationValues Contains both keys for each input and output wire and the translation table.
	 * @throws InvalidKeyException In case the seed is an invalid key for the given PRG.
	 */
	public FastCircuitCreationValues garble(byte[] seed) throws InvalidKeyException;
		
	/**
	 * This method takes an array containing the <b> non garbled</b> values, both keys for all input wires and the party number which the inputs belong to. <p>
	 * This method then performs the lookup on the allInputWireValues according to the party number and returns the keys 
	 * of the corresponding input bits.
	 * @param ungarbledInputBits An array containing the <b> non garbled</b> value for each input wire of the given party number. 
	 * @param allInputWireValues The array containing both garbled values (keys) for each input wire.
	 * The input values are placed one after another, meaning that the input values are in the following format:
	 *  [k0,0   k0,1    k1,0   k1,1   k2,0   k2,1 ....] (while k0,1 is key 1 of wire 0).
	 * @param partyNumber The number of party which the inputs belong to.
	 * @return an array containing a single key of each input wire of the given party.
	 */
	public byte[] getGarbledInputFromUngarbledInput(byte[] ungarbledInputBits, byte[] allInputWireValues, int partyNumber) ;
 
	
	public void setInputs(byte[] garbledInputs);
	
	/**
	 * This method computes the circuit using the given inputs. <p>
	 * It returns an array containing the garbled output. This output can be translated via the {@link #translate(byte[])} method.
	 * @return returns an array containing the garbled value of each output wire.
	 * @throws NotAllInputsSetException if the given inputs array does not includes a key for all input wires.
	 */
	public byte[] compute() throws NotAllInputsSetException;

	/**
     * The verify method is used in the case of malicious adversaries.<p>
     * Alice constructs n circuits and Bob can verify n-1 of them (of his choice) to confirm that they are indeed garbling of the 
     * agreed upon non garbled circuit. In order to verify, Alice has to give Bob both keys for each of the input wires.
     * @param allInputWireValues An array containing both keys for each input wire.
     * The input values are placed one after another, meaning that the input values are in the following format:
	 *  [k0,0   k0,1    k1,0   k1,1   k2,0   k2,1 ....] (while k0,1 is key 1 of wire 0).
     * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling the given keys, {@code false} if it is not.
     */
	public boolean verify(byte[] allInputWireValues) ;

	/**
     * This function behaves exactly as the verify(byte[] allInputWireValues) method except the last part.
     * The verify function verifies that the translation table matches the resulted output garbled values, while this function does not check it 
     * but return the resulted output garbled values. 
     * @param allInputWireValues An array containing both keys for each input wire.
     * The input values are placed one after another, meaning that the input values are in the following format:
	 *  [k0,0   k0,1    k1,0   k1,1   k2,0   k2,1 ....] (while k0,1 is key 1 of wire 0).
     * @param allOutputWireValues An array containing both keys for each output wire. 
     * The output values are placed one after another, meaning that the output values are in the following format:
	 *  [k0,0   k0,1    k1,0   k1,1   k2,0   k2,1 ....] (while k0,1 is key 1 of wire 0).
     * When calling the function this array should be empty and will be filled during the process of the function.
     * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling the given keys, {@code false} if it is not.
     */
	public boolean internalVerify(byte[] allInputWireValues, byte[] allOutputWireValues);
	
	/**
	 * This function does the last part of the verify function. It gets both keys of each output wire and checks that 
	 * their signal bits match the corresponding bit in the translation table.<p>
	 * 
	 * The internalVerify function followed by this function are actually executes the whole verify of the circuit.
	 * @param allOutputWireValues both keys of each output wire.
	 * The output values are placed one after another, meaning that the output values are in the following format:
	 *  [k0,0   k0,1    k1,0   k1,1   k2,0   k2,1 ....] (while k0,1 is key 1 of wire 0).
	 * @return {@code true} if the given keys match the translation table ,{@code false} if not.
	 */
	public boolean verifyTranslationTable(byte[] allOutputWireValues);
	
	/**
	 * Translates the garbled output obtained from the {@link #compute()} function into a meaningful(i.e. 0-1) output.<p>
	 * @param garbledOutput An array contains the garbled output. 
	 * @return an array contains the output bit for each output wire.
	 */
	public byte[] translate(byte[] garbledOutput);
	
	/**
	 * Verifies that the given garbledOutput is valid values according to the given all OutputWireValues. <p>
	 * Meaning, for each output wire, checks that the garbled wire is one of the two possibilities.
	 * Then, translates the garbled output obtained from the {@link #compute()} function into a meaningful(i.e. 0-1) output.<p>
	 * @param garbledOutput An array contains the garbled output. 
	 * @param allOutputWireValues both values for each output wire.
	 * The output values are placed one after another, meaning that the output values are in the following format:
	 *  [k0,0   k0,1    k1,0   k1,1   k2,0   k2,1 ....] (while k0,1 is key 1 of wire 0).
	 * @return an array contains the output bit for each output wire.
	 * @throws CheatAttemptException if there is a garbledOutput values that is not one of the two possibilities.
	 */
	public byte[] verifiedTranslate(byte[] garbledOutput, byte[] allOutputWireValues) throws CheatAttemptException;

	
	/**
	 * The garbled tables are stored in the circuit for all the gates. This method returns the garbled tables. <p>
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and the translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and the translation tables if 
	 * necessary). The advantage is that the size of the tables only is much smaller that all the information stored in the circuit 
	 * (gates and other member variables). The size becomes important when sending large circuits.
	 * 
	 */
	public GarbledTablesHolder getGarbledTables();
	
	/**
	 * Sets the garbled tables of this circuit.<p>
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and the translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and the translation tables if necessary).
	 * The advantage is that the size of the tables only is much smaller that all the information stored in the circuit (gates and other 
	 * member variables). The size becomes important when sending large circuits.<p>
	 * The receiver of the circuits will set the garbled tables for the relevant circuit.
	 */
	public void setGarbledTables(GarbledTablesHolder garbledTables);
	
	/**
     * Returns the translation table of the circuit. <P>
     * This is necessary since the constructor of the circuit may want to pass the translation table to an other party. <p>
     * Usually, this will be used when the other party (not the constructor of the circuit) creates a circuit, sets the garbled tables 
     * and needs the translation table as well to complete the construction of the circuit.
     * @return the translation table of the circuit.  
     */
	public byte[] getTranslationTable();
  
	/**
	 * Sets the translation table of the circuit. <p>
	 * This is necessary when the garbled tables where set and we would like to compute the circuit later on. 
	 * @param translationTable This value should match the garbled tables of the circuit.
	 */
	public void setTranslationTable(byte[] translationTable);
	
	/**
	 * Returns the input wires' indices of the given party.
	 * @param partyNumber The number of the party which we need his input wire indices.
	 * @return an array contains the indices of the input wires of the given party number.
	 * @throws NoSuchPartyException In case the given party number is not valid.
	 */
	public int[] getInputWireIndices(int partyNumber) throws NoSuchPartyException;
	
	/**
	 * @return an array containing the indices of the circuit's output wires.
	 */
	public int[] getOutputWireIndices();
	
	/**
	 * @return an array containing the indices of the circuit's input wires.
	 */
	public int[] getInputWireIndices();

	/**
	 * Returns the number of input wires of the given party.
	 * @param partyNumber the number of the party which we need his number of inputs.
	 * @return the number of inputs of this circuit.
	 * @throws NoSuchPartyException In case the given party number is not valid.
	 */
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException; 
	
	/**
	 * Returns the number of parties using this circuit.
	 * 
	 */
	public int getNumberOfParties();

	/**
	 * 
	 * @return the size of the keys, in bytes.
	 */
	public int getKeySize();
}
