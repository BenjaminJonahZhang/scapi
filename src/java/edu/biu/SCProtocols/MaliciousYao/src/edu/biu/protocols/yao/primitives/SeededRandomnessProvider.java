package edu.biu.protocols.yao.primitives;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;

/**
 * This class creates and initializes SecureRandom objects to use in the protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class SeededRandomnessProvider {
	
	/*
	 * Unique seed for each needed secure random object.
	 */
	private static final int GARBLED_CIRCUIT_SEED_SOURCE = 1;
	private static final int P2_INPUT_KEYS_SEED_SOURCE = 3;
	private static final int MASKS_SEED_SOURCE = 4;
	private static final int COMMITMENTS_SEED_SOURCE = 5;

	private final byte[] seed;
	private final SecureRandom random;
	private final PseudorandomFunction prf;

	/**
	 * Creates a SecureRandom object using the given seed.
	 * @param seed Used to seed the created secure random object.
	 * @return The created SecureRandom object.
	 */
	public static SecureRandom getSeededSecureRandom(byte [] seed) {
		SecureRandom random = null;
		try {
			// The default algorithm for secure random does not return predictable bytes even
			// if the same seed is provided.
			random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(seed);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		return random;
	}
	
	/**
	 * A constructor that sets the inner members using the given seed.
	 * @param seed Used to initialize the inner members.
	 */
	public SeededRandomnessProvider(byte[] seed) {
		//Set the seed and the random member using it.
		this.seed = seed;
		this.random = getSeededSecureRandom(seed);
		
		//Create the prf member using the created random and set it with key.
		this.prf = new CryptoPpAES(random);
		SecretKey k = prf.generateKey(128);
		try {
			prf.setKey(k);
		} catch (InvalidKeyException e) {
			//Should not occur since the key was generated using the prf object itself.
		}
	}
	
	/**
	 * Returns the seed used to create the random.
	 */
	public byte[] getSeed() {
		return seed;
	}
	
	/**
	 * Create a SecureRandom object that initialized in order to garble a circuit.
	 * @return the created random.
	 */
	public SecureRandom getGarblingSecureRandom() {
		return createRandomFromSource(GARBLED_CIRCUIT_SEED_SOURCE);
	}
	
	/**
	 * Create a SecureRandom object that initialized in order to generate p2 keys.
	 * @return the created random.
	 */
	public SecureRandom getP2InputKeysSecureRandom() {
		return createRandomFromSource(P2_INPUT_KEYS_SEED_SOURCE);
	}
	
	/**
	 * Create a SecureRandom object that initialized in order to generate masks.
	 * @return the created random.
	 */
	public SecureRandom getMasksSecureRandom() {
		return createRandomFromSource(MASKS_SEED_SOURCE);
	}
	
	/**
	 * Create a SecureRandom object that initialized in order to generate commitments.
	 * @return the created random.
	 */
	public SecureRandom getCommitmentsSecureRandom() {
		return createRandomFromSource(COMMITMENTS_SEED_SOURCE);
	}
	
	/**
	 * Create a byte array using the source integer.
	 * @param source The integer to use in order to create the array.
	 * @return the created byte array.
	 */
	private byte[] createBytesFromSource(int source) {
		
		//Create an array of size block.
		byte[] bytes = new byte[prf.getBlockSize()];
		//Fill each cell in the array with source & 1 and shift source to the right.
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) (source & 1);
			source >>= 1;
		}
		
		return bytes;
	}
	
	/**
	 * Create a pseudo random object using the source integer.
	 * @param source The integer to use in order to create the array.
	 * @return the created byte array.
	 */
	private SecureRandom createRandomFromSource(int source) {
		//Create byte array from the source.
		byte[] newSeed = new byte[prf.getBlockSize()];
		byte[] inBytes = createBytesFromSource(source);
		
		//Use the prf to generate pseudo random bytes from the created array.
		try {
			prf.computeBlock(inBytes, 0, newSeed, 0);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalStateException(e);
		}
		
		//Return new random using the new seed. 
		return getSeededSecureRandom(newSeed);
	}
}
