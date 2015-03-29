package edu.biu.protocols.yao.common;

import edu.biu.scapi.exceptions.InvalidInputException;

/**
 * This class provides some binary utilities to use in the protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class BinaryUtils {
	
	/**
	 * Returns a byte array that is the binary representation of the given byte[].
	 * @param bytes array to get the binary representation of.
	 */
	public static byte[] getBinaryByteArray(byte [] bytes) {
    	int numBits = bytes.length * Byte.SIZE;
    	byte [] binary = new byte[numBits];
        for(int i = 0; i < numBits; i++) {
        	// Take the byte the current bit belongs to.
        	byte currentByte = bytes[i / Byte.SIZE];
        	// Shift by the current bit's index within the byte.
        	int shiftBy = i % Byte.SIZE;
        	// Mask the entire value up to this bit.
        	int mask = 0x80;
        	// If the bit is zero the entire value will be zero.
        	// Cast the result back to byte (numbers are int by default).
        	binary[i] = (byte) ((currentByte << shiftBy & mask) == 0 ? 0 : 1);
        }
        return binary;
    }
	
	/**
	 * Returns the result of the XOR of given arrays.
	 * @param k1
	 * @param k2
	 * @throws InvalidInputException
	 */
	public static byte[] xorArrays(byte[] k1, byte[] k2) throws InvalidInputException {
		byte[] result = new byte[k1.length];
		
		//Check that the lengths are equal.
		if (k1.length != k2.length) {
			throw new InvalidInputException();
		}
		
		//Xor each byte.
		for (int i = 0; i < k1.length; i++) {
			result[i] = (byte) (k1[i] ^ k2[i]);
		}
		return result;
	}
}