package edu.biu.protocols.yao.offlineOnline.primitives;

import java.security.InvalidKeyException;

import javax.crypto.SecretKey;

import edu.biu.protocols.yao.common.BinaryUtils;
import edu.biu.protocols.yao.primitives.CircuitInput;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastCircuitCreationValues;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidInputException;

/**
 * This class builds the bundle of the Cheating recover circuit. <p>
 * 
 * It derives the BundleBuilder class and add the proof of cheating functionalities.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CheatingRecoveryBundleBuilder extends BundleBuilder {

	private final CircuitInput proofOfCheating;	// A proof that the other party is cheating.

	/**
	 * A constructor that sets the parameters.
	 * @param gbc The garbled circuit to use in the bundle.
	 * @param matrix The matrix used to extends y1 keys.
	 * @param primitives Provides the primitives that are used in the protocol, such as hash function.
	 * @param channel The channel communicate between the parties.
	 * @param proofOfCheating A proof that the other party is cheating.
	 */
	public CheatingRecoveryBundleBuilder(FastGarbledBooleanCircuit gbc, KProbeResistantMatrix matrix, CryptoPrimitives primitives, Channel[] channels, SecretKey proofOfCheating) {
		super(gbc, matrix, primitives, channels);
		this.secret = proofOfCheating;
		this.proofOfCheating = CircuitInput.fromSecretKey(proofOfCheating);
	}

	@Override
	protected FastCircuitCreationValues garble() {
	
		FastCircuitCreationValues wireValues = null;
		byte[] seed = new byte[keySize]; 
		randomGarble.nextBytes(seed);
			
		// garble the circuit.
		try {
			wireValues = gbc.garble(seed);
		} catch (InvalidKeyException e) {
			// Should not occur since the seed is in the right size.
			throw new IllegalStateException();
		}
		
		//Fill inputWiresX from the output of the garble function.
		inputWiresX = new byte[inputLabelsX.length*2*keySize];		
		System.arraycopy(wireValues.getAllInputWireValues(), 0, inputWiresX, 0, 2*keySize*inputLabelsP1.length);

		// Override P2 input keys with the secret sharing input keys.
		inputLabelsY2 = proofOfCheating.getLabels();
		inputWiresY = new byte[inputLabelsY2.length*2*keySize];
		inputWiresY1 = new byte[inputLabelsY2.length*2*keySize];
		inputWiresY2 = new byte[inputLabelsY2.length*2*keySize];
		
		// Obtain the master key and generate P2 keys according to the master key.
		byte[] masterKey = new byte[keySize];
		System.arraycopy(wireValues.getAllInputWireValues(), (2*inputLabelsP1.length+1)*keySize, masterKey, 0, keySize);
		
		generateYKeys(masterKey, proofOfCheating.asByteArray());
		
		//Split P2 keys into Y1 and Y2 keys.
		splitKeys();
		
		//Fill inputWiresY1Extended keys using the matrix.
		inputWiresY1Extended = matrix.transformKeys(inputWiresY1, mesP2InputKeys);
		
		return wireValues;	
	}

	/**
	 * Generates P2 keys according to the master key.
	 * @param masterKey The one key of P1.
	 * @param sigmaArray bytes of proof of cheating.
	 */
	private void generateYKeys(byte[] masterKey, byte[] sigmaArray) {
		
		int numShares = inputLabelsY2.length;	//number of P2 input wires.
		int lastIndex = numShares - 1;
		
		byte[] xorOfShares = null;
		byte[] currentKey = null;
		byte[][] lastSharePair = new byte[2][];
		
		//Generate both keys for each p2 wire.
		for (int i = 0; i < lastIndex; i++) {
			//Generate two random keys.
			byte[] key0 = mesP2InputKeys.generateKey().getEncoded();
			byte[] key1 = mesP2InputKeys.generateKey().getEncoded();
			System.arraycopy(key0, 0, inputWiresY, i*2*keySize, keySize);
			System.arraycopy(key1, 0, inputWiresY, (i*2+1)*keySize, keySize);
			
			//Get the key that matches the sigma of this wire.
			if (sigmaArray[i] == 1){
				currentKey = key1;
			} else{
				currentKey = key0;
			}
			if (i == 0) {
				// The xor of just the first key is the first key.
				xorOfShares = currentKey;
			} else {
				// The xor of the current key with the previous xor is the xor of all keys.
				try {
					xorOfShares = BinaryUtils.xorArrays(xorOfShares, currentKey);
				} catch (InvalidInputException e) {
					throw new IllegalStateException(e);
				}
			}
		}
		
		//The last pair of keys is the Xor of all sigma keys with the master key and a random key.
		try {
			lastSharePair[sigmaArray[lastIndex]] = BinaryUtils.xorArrays(xorOfShares, masterKey);
			lastSharePair[1-sigmaArray[lastIndex]] = mesP2InputKeys.generateKey().getEncoded(); // The other share is random
			
		} catch (InvalidInputException e) {
			throw new IllegalStateException(e);
		}
		System.arraycopy(lastSharePair[0], 0, inputWiresY, lastIndex*2*keySize, keySize);
		System.arraycopy(lastSharePair[1], 0, inputWiresY, (lastIndex*2+1)*keySize, keySize);
	}
		
	
}
