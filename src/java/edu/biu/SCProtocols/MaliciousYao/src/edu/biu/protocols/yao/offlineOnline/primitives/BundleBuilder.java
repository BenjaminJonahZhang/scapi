package edu.biu.protocols.yao.offlineOnline.primitives;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import edu.biu.protocols.yao.common.BinaryUtils;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.protocols.yao.primitives.SeededRandomnessProvider;
import edu.biu.scapi.circuits.encryption.AESFixedKeyMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastCircuitCreationValues;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashCommitter;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;

/**
 * This class builds the bundle. <p>
 * Unlike the Bundle class (that is just a struct that hold data), this class also has functionality that creates 
 * the inline members. <p>
 * 
 * It contains a build function that garbles the circuit, commit on the keys, etc.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class BundleBuilder {
	protected final FastGarbledBooleanCircuit gbc;
	public final KProbeResistantMatrix matrix;
	protected final CryptoPrimitives primitives;
	protected final Channel[] channels;
	protected final SecureRandom random;
	protected int keySize;
	
	// Labels.
	protected int[] inputLabelsP1;
	protected int[] inputLabelsP2;
	protected final int[] probeResistantLabels;
	protected int[] outputLabels;
	
	// Randomness.
	protected MultiKeyEncryptionScheme mesP2InputKeys;
	protected SecureRandom randomSourceMasks;
	protected SecureRandom randomSourceCommitments;
	protected SecureRandom randomGarble;
	
	// Wires.
	protected byte[] inputWiresX;
	protected byte[] inputWiresY;
	protected byte[] inputWiresY1;
	protected byte[] inputWiresY1Extended;
	protected byte[] inputWiresY2;
	protected SecretKey secret;
	
	// Wire's indices.
	protected int[] inputLabelsX;
	protected int[] inputLabelsY1Extended;
	protected int[] inputLabelsY2;
	
	private CmtCCommitmentMsg commitment;
	private CmtCDecommitmentMessage decommit;
	/**
	 * A constructor that sets the parameters.
	 * @param gbc The garbled circuit to use in the bundle.
	 * @param matrix The matrix used to extends y1 keys.
	 * @param primitives Provides the primitives that are used in the protocol, such as hash function.
	 * @param channel The channel communicate between the parties.
	 */
	public BundleBuilder(FastGarbledBooleanCircuit gbc, KProbeResistantMatrix matrix, CryptoPrimitives primitives, Channel[] channels) {
		this.gbc = gbc;
		this.matrix = matrix;
		this.primitives = primitives;
		this.channels = channels;
		this.random = primitives.getSecureRandom();
		
		// Fixed labels.
		this.probeResistantLabels = matrix.getProbeResistantLabels();
		
		this.secret = null;
	}
	
	/**
	 * Builds the Bundle, meaning garble the inner circuit, commit on it keys, etc.
	 * @param seedSizeInBytes The size of the required seed.
	 * @return The created Bundle.
	 */
	public Bundle build(int seedSizeInBytes) {
		//Generate a seed.
		byte[] seed = random.generateSeed(seedSizeInBytes);
		//Build the Bundle.
		return build(seed);
	}
	
	/**
	 * Builds the Bundle using the given seed.
	 * @param seed To use in the build process.
	 * @return The created Bundle.
	 */
	public Bundle build(byte[] seed) {
	
		//Initialize the random sources with the given seed.
		initRandomness(seed);
	
		//Get the input and output wire's indices.
		try {
			this.inputLabelsP1 = gbc.getInputWireIndices(1);
			this.inputLabelsP2 = gbc.getInputWireIndices(2);
		} catch (NoSuchPartyException e) {
			// Should not occur.
		}
		this.outputLabels = gbc.getOutputWireIndices();
		
		// Effective labels after manipulation.
		inputLabelsY1Extended = probeResistantLabels;
		inputLabelsX = inputLabelsP1;
		inputLabelsY2 = inputLabelsP2;

		//Garble the circuit.
		FastCircuitCreationValues wireValues = garble();

		// Creates m, the size of m is the same as x.
		byte[] placementMask = generatePlacementMask();
		// Create lambda, the size of lambda is the same as the size of an input wire key.
		byte[] commitmentMask = getRandomVector(randomSourceMasks, keySize);

		//Commit on the keys.
		CommitmentBundleBuilder commitmentBuilder = new CommitmentBundleBuilder(randomSourceCommitments, primitives, null, keySize); 
		CommitmentBundle commitmentsX = commitmentBuilder.build(inputWiresX, inputLabelsX, commitmentMask, placementMask);
		CommitmentBundle commitmentsY1Extended = commitmentBuilder.build(inputWiresY1Extended, inputLabelsY1Extended, commitmentMask);
		CommitmentBundle commitmentsY2 = commitmentBuilder.build(inputWiresY2, inputLabelsY2, commitmentMask);
		//The commitments on the output keys can be done once and not for each wire separately.
		commitOutputs(wireValues.getAllOutputWireValues());
		
		//Create and return a new Bundle with the built data.
		return new Bundle.Builder(seed, keySize)
		.circuit(gbc, wireValues)
		.masks(placementMask, commitmentMask)
		.labels(inputLabelsX, inputLabelsY1Extended, inputLabelsY2, outputLabels)
		.wires(inputWiresX, inputWiresY1Extended, inputWiresY2)
		.commitments(commitmentsX, commitmentsY1Extended, commitmentsY2, commitment, decommit)
		.secret(secret)
		.build();
	}
	
	/**
	 * Commit the output keys at once by committing the array contain all keys.
	 * @param allOutputWireValues the array to commit on.
	 */
	private void commitOutputs(byte[] allOutputWireValues) {
		//Create teh committer object.
		CryptographicHash hash = new CryptoPpSHA1();
		CmtCommitter committer = new CmtSimpleHashCommitter(null, hash, randomSourceCommitments, hash.getHashedMsgSize());
		CmtCommitValue commitValue;
				
		//Generate the commit value.
		try {
			commitValue = committer.generateCommitValue(allOutputWireValues);

		} catch (CommitValueException e) {
			throw new IllegalStateException(e);
		}
		
		//Commit and decommit on the keys. The commitment and decommitment objects are saved as class members.
		commitment = committer.generateCommitmentMsg(commitValue, 0);
		decommit = committer.generateDecommitmentMsg(0);

	}

	/**
	 * Generates a placement mask, which is the signal bits of each wire.
	 * @return the generates mask.
	 */
	private byte[] generatePlacementMask() {
		
		//The placement mask contains, for each input wire of the first party, the last byte of k1 & 1.
		byte[] placementMask = new byte[inputLabelsP1.length];
		for (int i=0; i<inputLabelsP1.length; i++){
			placementMask[i] = (byte) (inputWiresX[(2*i+1)*keySize - 1] & 1);
		}
		return placementMask;
	}

	/**
	 * Initializes some random sources that are used in the build process.
	 * @param seed To use in order to initialize the random object.
	 */
	private void initRandomness(byte[] seed) {
		//Create a random provider object.
		SeededRandomnessProvider randomProvider = null;
		randomProvider = new SeededRandomnessProvider(seed);
		
		//Generate keys and random sources.
		mesP2InputKeys = new AESFixedKeyMultiKeyEncryption(new CryptoPpAES(randomProvider.getP2InputKeysSecureRandom()));
		randomSourceMasks = randomProvider.getMasksSecureRandom();
		randomSourceCommitments = randomProvider.getCommitmentsSecureRandom();
		randomGarble = randomProvider.getGarblingSecureRandom();
		keySize = mesP2InputKeys.getCipherSize();
	}
	
	/**
	 * Garbles the circuit, then set keys to the additional wires in the protocol.
	 * @return The output of the garble function.
	 */
	protected FastCircuitCreationValues garble() {
		
		byte[] seed = new byte[16]; 
		randomGarble.nextBytes(seed);
		
		FastCircuitCreationValues values = null;
		// garble the circuit.
		try {
			values = gbc.garble(seed);
			
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		
		inputWiresX = new byte[inputLabelsP1.length*2*keySize];
		inputWiresY = new byte[inputLabelsP2.length*2*keySize];
		inputWiresY1 = new byte[inputLabelsP2.length*2*keySize];
		inputWiresY2 = new byte[inputLabelsP2.length*2*keySize];
		
		//Fill inputWiresX and inputWiresY from the output of the garble function.
		System.arraycopy(values.getAllInputWireValues(), 0, inputWiresX, 0, 2*keySize*inputLabelsP1.length);
		System.arraycopy(values.getAllInputWireValues(), 2*keySize*inputLabelsP1.length, inputWiresY, 0, 2*keySize*inputLabelsP2.length);
		
		//Split Y keys into Y1 and Y2 keys.
		splitKeys();
			
		//Fill inputWiresY1Extended keys using the matrix.
		inputWiresY1Extended = matrix.transformKeys(inputWiresY1, mesP2InputKeys);
		
		return values;
	}

	/**
	 * Split Y keys into Y1 and Y2 keys.
	 */
	protected void splitKeys() {
			
		byte[] yDelta = null;
		byte[] y0 = new byte[keySize];
		byte[] y1 = new byte[keySize];
		
		//1. Get both keys of each wire (y0, y1)
		//2. Choose a random key w0
		//3. Compute z0 = y0, w0
		//			 w1 = w0 ^ delta
		//			 z1 = z0 ^ delta
		//4. set (k0, k1) to be one set of keys to Y0 and (z0,z1) to bw set of keys to Y2.
		for (int i = 0; i < inputLabelsP2.length; i++) {
			//get Y0, y1.
			System.arraycopy(inputWiresY, i*2*keySize, y0, 0, keySize);
			System.arraycopy(inputWiresY, (i*2+1)*keySize, y1, 0, keySize);
			
			//In case this is the first time, get delta = y0^y1.
			if (yDelta == null){
				try {
					yDelta = BinaryUtils.xorArrays(y0, y1);
				} catch (InvalidInputException e1) {
					//Should not occur sine the keys have the same length.
				}
			}
			
			byte[] w0 = new byte[keySize];
			byte[] w1 = new byte[keySize];
			byte[] z0 = new byte[keySize];
			byte[] z1 = new byte[keySize];
			
			//Generate random key.
			w0 = mesP2InputKeys.generateKey().getEncoded();
			try {
				// w0 ^ z0 complete to y0.
				z0 = BinaryUtils.xorArrays(y0, w0);
				// w1 = w0 ^ delta(y0,y1).
				w1 = BinaryUtils.xorArrays(w0, yDelta);
				// z1 = z0 ^ delta(y0,y1).
				z1 = BinaryUtils.xorArrays(z0, yDelta);
			} catch (InvalidInputException e) {
				throw new IllegalStateException(e);
			}
			
			//Copy the results into the class members (which are long arrays.)
			System.arraycopy(w0, 0, inputWiresY1, keySize*i*2, keySize);
			System.arraycopy(w1, 0, inputWiresY1, keySize*(i*2+1), keySize);
			System.arraycopy(z0, 0, inputWiresY2, keySize*i*2, keySize);
			System.arraycopy(z1, 0, inputWiresY2, keySize*(i*2+1), keySize);
		}
	}
	
	/**
	 * Create a random binary vector (e.g. each element is 0/1).
	 * @param random Source of randomness to use.
	 * @param size the required bytes in the new vector.
	 * @return The created array.
	 */
	protected byte[] getRandomVector(SecureRandom random, int size) {
		//Create the array in the requested size.
		byte[] vector = new byte[size];
		//fill each byte with 0/1.
		for (int i = 0; i < vector.length; i++) {
			vector[i] = (byte) random.nextInt(2);
		}
		return vector;
	}

	
	
}