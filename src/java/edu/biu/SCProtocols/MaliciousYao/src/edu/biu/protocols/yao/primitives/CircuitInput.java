package edu.biu.protocols.yao.primitives;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKey;

import edu.biu.protocols.yao.common.BinaryUtils;
import edu.biu.protocols.yao.common.CircuitUtils;
import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.comm.ProtocolInput;

/**
 * This class Manages the input of the circuit. <P>
 * 
 * It contains the wires' indices the input bytes for each wire index.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CircuitInput implements ProtocolInput, Serializable {
	private static final long serialVersionUID = -9738674180166972L;
	
	private byte[] input;			//The input for each wire.
	private int[] labels;			//The indices of the wires.
	
	/**
	 * A constructor that sets the given input for the given wires.
	 * @param inputBits The input for each wire.
	 * @param wireLabels The indices of the wires.
	 */
	public CircuitInput(byte[] inputBits, int[] wireLabels) {
		Preconditions.checkNotZero(inputBits.length);
		Preconditions.checkArgument(inputBits.length == wireLabels.length);
		
		input = inputBits;
		for (int i = 0; i < inputBits.length; i++) {
			Preconditions.checkBinary(inputBits[i]);
		}
		labels = wireLabels;
	}
	
	/**
	 * Alternative constructor. <P>
	 * It creates new CircuitInput object with the given input and a new wire indices array such as the indices are [0, ..., input.length].
	 * @param inputArray  The input for each wire.
	 * @return the created CircuitInput object.
	 */
	public static CircuitInput fromByteArray(byte[] inputArray) {
		int[] wireLabels = new int[inputArray.length];
		
		//Crate an indices array from 0 to inputArray.length.
		for (int i = 0; i < inputArray.length; i++) {
			wireLabels[i] = i;
		}
		
		//Create a new CircuitInput object and return it.
		return new CircuitInput(inputArray, wireLabels);
	}
	
	/**
	 * Alternative constructor. <P>
	 * It creates new CircuitInput object and read the input from the given file.
	 * @param filename The name of the file to read the inputs from.
	 * @param bc The circuit to get the inputs for.
	 * @param party the party number which the inputs belongs.
	 * @return the created CircuitInput object.
	 */
	public static CircuitInput fromFile(String filename, BooleanCircuit bc, int party) throws FileNotFoundException {
		// Create a scanner to read from the file.
		Scanner scanner = new Scanner(new File(filename));
		
		// Get the number of inputs for this party.
		int numberOfInputs = scanner.nextInt();
		byte[] inputBits = new byte[numberOfInputs];
		
		// Read each integer and immediately cast to a byte.
		for (int i = 0; i < numberOfInputs; i++) {
			int bit = scanner.nextInt();
			inputBits[i] = (byte) bit;
		}
		scanner.close();
		
		//Create the indices array.
		ArrayList<Integer> indices = CircuitUtils.getLabels(bc, party);
		int[] intArr = new int[indices.size()];
		for (int i=0; i< intArr.length; i++){
			intArr[i] = indices.get(i);
		}
		
		//Create a new CircuitInput object from the inputs and indices arrays and return it.
		return new CircuitInput(inputBits, intArr);
	}
	
	/**
	 * Alternative constructor. <P>
	 * It creates new CircuitInput object and sets random inputs.
	 * @param labels The indices of the wires.
	 * @return the created CircuitInput object.
	 */	
	public static CircuitInput randomInput(int[] labels) {
		//Create a new input array.
		byte[] inputBits = new byte[labels.length];
		SecureRandom random = new SecureRandom();
		
		//Generate random inputs for each wire.
		for (int i = 0; i < labels.length; i++) {
			inputBits[i] = (byte) random.nextInt(2);
		}
		
		//Create a new CircuitInput object from the inputs and indices arrays and return it.
		return new CircuitInput(inputBits, labels);
	}
	
	/**
	 * Alternative constructor. <P>
	 * It creates new CircuitInput object and sets the inputs from the given key.
	 * @param inputKey The key that used to get the inputs.
	 * @return the created CircuitInput object.
	 */	
	public static CircuitInput fromSecretKey(SecretKey inputKey) {
		//Set the encoded key as the circuit inputs.
		byte[] inputBinaryArray = BinaryUtils.getBinaryByteArray(inputKey.getEncoded());
		
		//Create the labels of the circuit.
		int[] inputLabels = new int[inputBinaryArray.length];
		for (int i = 0; i < inputBinaryArray.length; i++) {
			inputLabels[i] = i+1; // labels start at "1".
		}
		//Create a new CircuitInput object from the inputs and indices arrays and return it.
		return new CircuitInput(inputBinaryArray, inputLabels);
	}
	
	/**
	 * Returns the size of the inputs.
	 */
	public int size() {
		return input.length;
	}
	
	/**
	 * Returns the N'th input bit.
	 * @param n the index of the wire to get the input of.
	 */
	public byte getNthBit(int n) {
		return input[n];
	}
	
	/**
	 * Returns a map that contains the input for each wire.
	 */
	public Map<Integer, Wire> getInputWires() {
		//Create a map
		Map<Integer, Wire> wires = new HashMap<Integer, Wire>();
		//Put in the map the wire labe lalong with the input for this wire.
		for (int i=0; i<input.length; i++) {
			wires.put(labels[i], new Wire(input[i]));
		}
		return wires;
	}
	
	/**
	 * Returns the wire labels.
	 */
	public int[] getLabels() {
		return labels;
	}
	
	/**
	 * Returns the inputs for the wires.
	 */
	public byte[] asByteArray() {
		return input;
	}
	
	/**
	 * Returns the xor of the inputs in the two given CircuitInputs objects.
	 * @param x1 The first input to xor with the other.
	 * @param x2 The second input to xor with the other.
	 * @return the xor result.
	 */
	public static byte[] xor(CircuitInput x1, CircuitInput x2) {
		//Check hat the sizes of inputs are equal.
		Preconditions.checkArgument(x1.size() == x2.size());
		
		//Get both arrays of inputs.
		byte[] arr1 = x1.asByteArray();
		byte[] arr2 = x2.asByteArray();
		int n = arr1.length;
		
		//Xor the inputs arrays.
		byte[] result = new byte[n]; 
		for (int i = 0; i < n; i++) {
			result[i] = (byte) (arr1[i] ^ arr2[i]);
		}
		
		return result;
	}
}
