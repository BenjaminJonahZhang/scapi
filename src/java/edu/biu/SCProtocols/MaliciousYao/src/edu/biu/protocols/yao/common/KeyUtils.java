package edu.biu.protocols.yao.common;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;

/**
 * This class provides some utilities regarding keys in order to use in the protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public final class KeyUtils {
	
	/**
	 * Hashes the given key, then convert the result to a new key.
	 * @param key The key to hash.
	 * @param hash The hash function to use.
	 * @param kdf The kdf object to use in order to convert the hash result into a new key.
	 * @param keyLength The required length of the new key.
	 * @return The new key.
	 */
	public static SecretKey hashKey(SecretKey key, CryptographicHash hash, KeyDerivationFunction kdf, int keyLength) {
		//Create a ne wbyte array to hold the hash result.
		byte[] encodedKey = new byte[hash.getHashedMsgSize()];
		//Hash the given key.
		hash.update(key.getEncoded(), 0, key.getEncoded().length);
		hash.hashFinal(encodedKey, 0);
		
		//Convert the hash result into a new key and return it.
		return kdf.deriveKey(encodedKey, 0, encodedKey.length, keyLength); // resized back to the circuit key length
	}
    
    /**
     * XOR the two given key and return the resulted key.
     * @param k1
     * @param k2
     * @throws InvalidInputException if the lengths of the given keys are different.
     */
    public static SecretKey xorKeys(SecretKey k1, SecretKey k2) throws InvalidInputException {
    	//Get the encoded keys.
		byte[] k1Encoded = k1.getEncoded();
		byte[] k2Encoded = k2.getEncoded();
		byte[] resultEncoded = new byte[k1Encoded.length];
		
		//Check that the lengths of the keys are equal.
		if (k1Encoded.length != k2Encoded.length) {
			throw new InvalidInputException();
		}
		
		//Xor each byte.
		for (int i = 0; i < k1Encoded.length; i++) {
			resultEncoded[i] = (byte) (k1Encoded[i] ^ k2Encoded[i]);
		}
		
		//Convert the result to SecretKey and return it.
		return new SecretKeySpec(resultEncoded, "");
	}
    
    /**
     * Checks if the given keys are equal.
     * @param k1
     * @param k2
     * @return true in case the keys are equal; false, otherwise.
     */
    public static boolean compareKeys(SecretKey k1, SecretKey k2) {
    	//Compare the encoded keys.
		return Arrays.equals(k1.getEncoded(), k2.getEncoded());
    }
}
