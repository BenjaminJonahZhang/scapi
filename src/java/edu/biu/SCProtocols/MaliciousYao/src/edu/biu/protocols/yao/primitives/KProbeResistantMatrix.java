package edu.biu.protocols.yao.primitives;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;

/**
 * This class represents the K probe-resistant matrix that described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for 
 * Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, Definition 2.1. <P>
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class KProbeResistantMatrix implements Serializable {
	
	/**
	 * Native function that restore the original keys using the matrix from the given keys.
	 * @param receivedKeys the transformed keys.
	 * @param matrix The K probe-resistant matrix to use in order to restore the keys.
	 * @param n matrix's rows.
	 * @param m matrix's columns.
	 * @param retoredKeys The result keys of the function.
	 */
	private native void restoreKeys(byte[] receivedKeys, byte[][] matrix, int n, int m, byte[] retoredKeys);
	
	/**
	 * Native function that transform the original keys into the extended keys using the matrix.
	 * @param originalKeys the keys to transform.
	 * @param probeResistantKeys the transformed keys. Will be filled during the function execution.
	 * @param n matrix's rows.
	 * @param m matrix's columns.
	 * @param matrix The K probe-resistant matrix to use in order to restore the keys.
	 */
	private native void transformKeys(byte[] originalKeys, byte[] probeResistantKeys, byte[] seed, int n, int m, byte[][] matrix);
	
	private static final long serialVersionUID = 5332169146342967655L;
	
	private final byte[][] matrix; 	//The K probe-resistant matrix.
	private final int n;			//Number of matrix's rows.
	private final int m;			//Number of matrix's columns.
	
	/**
	 * A constructor that sets the given matrix.
	 */
	public KProbeResistantMatrix(byte[][] matrix) {
		Preconditions.checkNotNull(matrix);
		Preconditions.checkNotZero(matrix.length);
		
		this.matrix = matrix;
		this.n = matrix.length;
		this.m = matrix[0].length;
	}
	
	/**
	 * Returns the probe resistant input size (the matrix columns).
	 * 
	 */
	public int getProbeResistantInputSize() {
		return m;
	}
	
	/**
	 * Returns array of size m, when each cell i contains "i".
	 */
	public int[] getProbeResistantLabels() {
		int[] labels = new int[m];
		for (int i = 0; i < m; i++) {
			labels[i] = i;
		}
		return labels;
	}
	
	/**
	 * Gets a original keys and transform them into keys that corresponds to the matrix.
	 * @param originalKeys The keys that matched the rows of the matrix.
	 * @param mes used to generate new keys.
	 * @return the transformed keys, that matched the columns of the matrix.
	 */
	public byte[] transformKeys(byte[] originalKeys, MultiKeyEncryptionScheme mes) {
		int keySize = mes.getCipherSize();
		Preconditions.checkArgument(originalKeys.length/keySize/2 == n);
		
		//Create an array to hold the new keys. The are two keys for each of the matrix columns.
		byte[] probeResistantKeys = new byte[m*2*keySize];
		
		//Generate new keys using the encryption scheme.
		byte[] seed = mes.generateKey().getEncoded();
		
		//Call the native function that transform the keys.
		transformKeys(originalKeys, probeResistantKeys, seed, n, m, matrix);
		
		//Return the new transformed keys.
		return probeResistantKeys;
	}
	
	/**
	 * Gets a original inputs and transform them into inputs that corresponds to the matrix columns.
	 * @param originalInput The inputs that matched the rows of the matrix.
	 * @param random used to generate new inputs.
	 * @return the transformed inputs, that matched the columns of the matrix.
	 */
	public CircuitInput transformInput(CircuitInput originalInput, SecureRandom random) {
		Preconditions.checkArgument(n == originalInput.size());
		byte[] input = originalInput.asByteArray();
		byte[] newInput = new byte[m];
		
		// Init the new vector with -1 values.
		for (int j = 0; j < newInput.length; j++) {
			newInput[j] = -1;
		}
		
		// For each input bit of the original input:
		for (int i = 0; i < input.length; i++) {
			// Go over the line i in the matrix, and also over the new input vector.
			int lastIndexInTheLine = -1;
			int xorOfAllocatedBits = 0;
			
			for (int j = 0; j < m; j++) {
				if (0 == matrix[i][j]) {
					// The j^th bit in the new vector is **insignificant** to the i^th bit in the old vector/
					continue; // This bit is NOT added to the XOR.
				}
				// If we got here we deal with a significant bit.
				// A significant bit is ALWAYS added to the XOR.
				if (newInput[j] == -1) {
					// This bit is not yet allocated.
					lastIndexInTheLine = j; // Use this variable to negate the case where all bits are already allocated.
					newInput[j] = (byte) random.nextInt(2); // A random binary int.
				}
				xorOfAllocatedBits = xorOfAllocatedBits ^ newInput[j];
			}
			
			if (lastIndexInTheLine == -1) {
				// An unallocated bit on the line was not found or have a zeros line in the matrix.
				// In any case this is an illegal state.
				throw new IllegalStateException("this is not a k-probe resistant matrix: could not transform input!");
			}
			
			// At this point all the bits in the line were allocated, but we may have a mistake with the last bit.
			// In that case we flip it to achieve the correct xor.
			if (xorOfAllocatedBits != input[i]) {
				newInput[lastIndexInTheLine] = (byte) (1 - newInput[lastIndexInTheLine]);
			}
		}
		
		// There may still be un-allocated (but insignificant bits). We must make sure newInput is a binary vector.
		for (int j = 0; j < newInput.length; j++) {
			if (-1 == newInput[j]) {
				newInput[j] = 0;
			}
		}
		
		return CircuitInput.fromByteArray(newInput);
	}
	
	/**
	 * Restores the original keys using the matrix from the transformed keys.
	 * @param receivedKeys the transformed keys.
	 * @return the original restored keys.
	 */
	public  byte[] restoreKeys(byte[] receivedKeys) {
		Preconditions.checkArgument(receivedKeys.length/16 == m);
	
		//Allocate space for the original keys.
		byte[] restoredKeysArray = new byte[16*n];

		//Call the native function that computes the restoring.
		restoreKeys(receivedKeys, matrix, n, m, restoredKeysArray);
		
		return restoredKeysArray;
	}
	
	/**
	 * Saves the matrix to a file.
	 * @param matrix The matrix to write to the file.
	 * @param filename The name of the file to write the matrix to.
	 * @throws IOException In case there was a problem during the writing of the matrix to the file.
	 */
	public static void saveToFile(KProbeResistantMatrix matrix, String filename) throws IOException {
		//Create the file using the file name.
		ObjectOutput output = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
		//Write the matrix.
		output.writeObject(matrix);
		output.close();		
	}
	
	/**
	 * Loads the matrix from a file.
	 * @param filename The name of the file to read the matrix from.
	 * @return The read matrix.
	 * @throws IOException In case there was a problem during the writing of the matrix to the file.
	 * @throws ClassNotFoundException 
	 */
	public static KProbeResistantMatrix loadFromFile(String filename) throws IOException, ClassNotFoundException {
		ObjectInput input = new ObjectInputStream(new BufferedInputStream(new FileInputStream(filename)));
		KProbeResistantMatrix matrix = (KProbeResistantMatrix) input.readObject();
		input.close();
		return matrix;
	}
	
	static {	 
		 //load the MaliciousYaoUtil jni dll that performs the native functions.
		 System.loadLibrary("MaliciousYaoUtil");
	}
}
