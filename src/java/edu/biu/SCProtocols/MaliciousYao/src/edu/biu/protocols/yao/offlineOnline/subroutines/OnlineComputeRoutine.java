package edu.biu.protocols.yao.offlineOnline.subroutines;

import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.protocols.yao.common.KeyUtils;
import edu.biu.protocols.yao.primitives.CircuitEvaluationResult;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;

/**
 * This class computes the circuits and returns the output.
 * 
 * It also achieves the proof of cheating in case not all the circuits output the same result.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class OnlineComputeRoutine implements ComputeCircuitsRoutine {

	private final FastGarbledBooleanCircuit[] garbledCircuits;		// The circuits to work on. There is one circuit per thread.
	
	// Primitives objects to use in the compute step.
	private final CryptographicHash hash;
	private final KeyDerivationFunction kdf;
	private final MultiKeyEncryptionScheme mes;
	private final int keyLength;
	private int numOfThreads;
	
	// The proof of cheating in case no all the circuits output the same result.
	private final byte[][][][] proofCiphers;
	private final SecretKey hashedProof;
	private final int[] outputLabels;
	
	// The output of the compute step.
	private HashMap<Integer, byte[]> computedOutputWires;
	private HashMap<Integer, byte[]> translations;
	private SecretKey proofOfCheating;
	private int correctCircuit = -1;
	
	/**
	 * A constructor that sets the given parameters.
	 * @param garbledCircuits The circuits to work on. There is one circuit per thread.
	 * @param primitives Primitives objects to use in the compute step.
	 * @param proofCiphers Used to extract the proof of cheating.
	 * @param hashedProof Used to extract the proof of cheating.
	 */
	public OnlineComputeRoutine(FastGarbledBooleanCircuit[] garbledCircuits, CryptoPrimitives primitives, byte[][][][] proofCiphers, SecretKey hashedProof) {
		//Sets the given prameters.
		this.garbledCircuits = garbledCircuits;
		
		this.hash = primitives.getCryptographicHash();
		this.kdf = primitives.getKeyDerivationFunction();
		this.mes = primitives.getMultiKeyEncryptionScheme();
		this.keyLength = mes.getCipherSize();
		
		this.proofCiphers = proofCiphers;
		this.hashedProof = hashedProof;
		//All output labels are the same in all circuits.
		this.outputLabels = garbledCircuits[0].getOutputWireIndices(); 
		
		this.computedOutputWires = new HashMap<Integer, byte[]>();
		this.translations = new HashMap<Integer, byte[]>();
		this.proofOfCheating = null;
		this.numOfThreads = primitives.getNumOfThreads();
	}
	
	@Override
	public void computeCircuits() {
		//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
		if (numOfThreads > 0){
			//In case the number of thread is less than the number of eval circuits, there is no point to create all the threads.
			//In this case, create only number of threads as the number of eval circuits and assign one circuit to each thread.
			int threadCount = (numOfThreads < garbledCircuits.length) ? numOfThreads : garbledCircuits.length;
			ComputeThread[] threads = new ComputeThread[threadCount];
			
			//Calculate the number of circuit in each thread and the remainder.
			int remain = garbledCircuits.length % threadCount;
			int numOfCircuits =  garbledCircuits.length / threadCount;
			
			//Create the threads and assign to each one the appropriate circuits.
			//The last thread gets also the remaining circuits.
			for (int j = 0; j < threadCount; j++) {
				if ((j < (threadCount - 1)) || (remain == 0) ){
					threads[j] = new ComputeThread(j*numOfCircuits, (j+1)*numOfCircuits);
				} else {
					threads[j] = new ComputeThread(j*numOfCircuits, garbledCircuits.length);
				}
				//Start all threads.
				threads[j].start();
			}
			
			//Wait until all threads finish their job.
			for (int j = 0; j < threadCount; j++) {
				try {
					threads[j].join();
				} catch (InterruptedException e) {
					throw new IllegalStateException();
				}
			}
			
		//In case no thread should be created, compute all the circuits directly.
		} else{
			computeCircuit(0, garbledCircuits.length);
		}
	}
	
	/**
	 * Inner thread class that compute the circuits in a separate thread.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya farbstein)
	 *
	 */
	public class ComputeThread extends Thread{
		
		private int from;				// The first circuit in the circuit list that should be computed.
		private int to;					// The last circuit in the circuit list that should be computed.
		
		/**
		 * Constructor that sets the parameters.
		 * @param from The first circuit in the circuit list that should be computed.
		 * @param to The last circuit in the circuit list that should be computed.
		 */
		public ComputeThread(int from, int to){
			this.from = from;
			this.to = to;
		}
		
		/**
		 * Computes the circuits from the start point to the end point in the circuit list.
		 */
		public void run() {
			computeCircuit(from, to);
		}
	}
	
	/**
	 * Computes the circuits from the start point to the end point in the circuit list.
	 * @param from The first circuit in the circuit list that should be computed.
	 * @param to The last circuit in the circuit list that should be computed.
	 */
	private void computeCircuit(int from, int to) {
		//Compute each circuit in the range.
		for (int i= from; i<to; i++){
			try {
				//Compute the circuit.
				byte[] output = garbledCircuits[i].compute();
				
				//Save the garbled output in the outputs map.
				synchronized (computedOutputWires) {
					computedOutputWires.put(i, output);
				}
			} catch (NotAllInputsSetException e) {
				throw new IllegalStateException();
			}
		}
	}

	@Override
	public CircuitEvaluationResult runOutputAnalysis() {
		for (int i=0; i<garbledCircuits.length; i++){
			
			translations.put(i, garbledCircuits[i].translate(computedOutputWires.get(i)));
		}
		
		// For each output wire
		for (int i = 0; i < outputLabels.length; i++) {
			// Get the set of valid outputs received on this wire.
			try {
				proofOfCheating = extractProofOfCheating(i);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
				continue;
			} 

			// If we received two different values on the same wire, it means the other party is cheating.
			if (null != proofOfCheating) {
				return CircuitEvaluationResult.FOUND_PROOF_OF_CHEATING;
			}
		}
		
		//In case there was no cheating, create dummy key.
		proofOfCheating = mes.generateKey();
		return CircuitEvaluationResult.VALID_OUTPUT;
	}

	@Override
	public byte[] getOutput() {
		//If there was no cheating, all circuits output the same result. 
		//Take it from the first circuit.
		return translations.get(correctCircuit);
	}
	
	public void setCorrectCircuit(int j){
		correctCircuit = j;
	}
	
	/**
	 * Returns the proof of cheating.
	 * In case there was no cheating, returns a dummy secret key.
	 */
	public SecretKey getProofOfCheating() {
		return proofOfCheating;
	}
	
	public byte[] getComputedOutputWires(int circuitIndex) {
		return computedOutputWires.get(circuitIndex);
	}
	
	/**
	 * Extract proof of cheating for the given wire index.
	 * If there was no cheating, return null key.
	 * @param wireIndex The wire index to check for cheating.
	 * @return the proof of cheating in case there was a cheating; null, otherwise.
	 * @throws InvalidKeyException
	 * @throws InvalidInputException
	 */
	private SecretKey extractProofOfCheating(int wireIndex) throws InvalidKeyException {
		byte[] k0 = null;
		byte[] k1 = null;
		
		int j0 = -1;
		int j1 = -1;
		
		int numCircuits = garbledCircuits.length;
		//for each circuit, get the output of the given wire.
		//If there are two circuits that returned different output, check that these output values reveals the same proof
		//(using the received proof ciphers).
		//Use the generated proof in order to get the hashed result and check if it matches the received one.
		for (int j = 0; j < numCircuits; j++) {
			//Get the index of the output.
			int wireValue = translations.get(j)[wireIndex];
			byte[] computedWire = new byte[keyLength];
			//Copy the output of this wire in this circuit.
			System.arraycopy(computedOutputWires.get(j), keyLength*wireIndex, computedWire, 0, keyLength);
			if (0 == wireValue) {
				k0 = computedWire;
				j0 = j;
			} else {
				k1 = computedWire;
				j1 = j;
			}
			
			//If there is a different circuit that return a different key, use them to get the proof of cheating.
			if ((null != k0) && (null != k1)) {
				byte[] c0 = proofCiphers[wireIndex][j0][0];
				byte[] c1 = proofCiphers[wireIndex][j1][1];
				
				byte[] p0 = new byte[keyLength];
				byte[] p1 = new byte[keyLength];
				for (int i=0; i<keyLength; i++){
					p0[i] = (byte) (k0[i] ^ c0[i]);
					p1[i] = (byte) (k1[i] ^ c1[i]);
				}
					
				SecretKey proof = null;
				try {
					proof = KeyUtils.xorKeys(new SecretKeySpec(p0, ""), new SecretKeySpec(p1, ""));
				} catch (InvalidInputException e) {
					// Should not occur since both keys were decrypted by the encryption scheme and they have the same length.
				}
				//Hash the proof and compare the result to the received hash result. 
				//If equal, then there was a cheating.
				SecretKey hashOnProof = KeyUtils.hashKey(proof, hash, kdf, keyLength);
				if (KeyUtils.compareKeys(hashOnProof, hashedProof)) {
					return proof;
				}
			}
		}
		return null;
	}
}
