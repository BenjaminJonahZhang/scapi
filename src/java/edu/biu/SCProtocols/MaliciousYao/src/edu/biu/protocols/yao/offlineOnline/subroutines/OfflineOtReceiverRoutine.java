package edu.biu.protocols.yao.offlineOnline.subroutines;

import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.CommitmentBundle;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.primitives.LimitedBundle;
import edu.biu.protocols.yao.primitives.CircuitInput;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ByteArrayRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

/**
 * Runs the receiver side of the malicious OT protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class OfflineOtReceiverRoutine {
	private final CryptoPrimitives primitives;							// Primitives objects to use during the protocol execution.
	private final OTExtensionMaliciousReceiver maliciousOtReceiver;		// The inner malicious OT receiver object.
	private final KProbeResistantMatrix matrix;							// Used to transform the inputs from Y1 to Y1 extended.
	private final int[] originalLabels;									// Labels of Y1 keys.
	private final int m;												// The size of the Y2 extended keys.
	private final BucketList<LimitedBundle> buckets;					// Contain the circuits.
	
	/*
	 * Needed lengths.
	 */
	private final int numBuckets;
	private final int bucketSize;
	private final int hashSize;
	private final int keySize;
	
	private CmtSimpleHashReceiver cmtReceiver;							//The receiver of the commitment protocol.
	
	/**
	 * A constructor that sets the class members.
	 * @param execution Contains some parameters used in the OT. For example the bucket size.
	 * @param primitives Primitives objects to use during the protocol execution.
	 * @param maliciousOtReceiver The inner malicious OT receiver object.
	 * @param matrix The matrix to convert the original Y1 input to the Y1 extended inputs.
	 * @param channel Used to communicate between the parties in the commitment protocol. 
	 * In the OT protocol the communication is done in the native code and not using this channel.
	 * @param buckets Contain the circuits.
	 */
	public OfflineOtReceiverRoutine(ExecutionParameters execution, CryptoPrimitives primitives, 
			OTExtensionMaliciousReceiver maliciousOtReceiver, KProbeResistantMatrix matrix,
			Channel channel, BucketList<LimitedBundle> buckets) {
		//Sets the parameters.
		this.primitives = primitives;
		this.maliciousOtReceiver = maliciousOtReceiver;
		this.matrix = matrix;
		this.buckets = buckets;
		
		this.numBuckets = execution.numberOfExecutions();
		this.bucketSize = execution.bucketSize();
		this.hashSize = primitives.getCryptographicHash().getHashedMsgSize();
		this.keySize = primitives.getMultiKeyEncryptionScheme().getCipherSize();
		this.m = matrix.getProbeResistantInputSize();
		this.originalLabels = buckets.getBundle(0, 0).getInputLabelsY2();
		
		//Creates the commitment receiver.
		try {
			this.cmtReceiver = new CmtSimpleHashReceiver(channel, primitives.getCryptographicHash(), hashSize);
		} catch (Exception e) {
			// No matter what the exception is, it is unexpected and thus illegal
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Generates inputs and runs the receiver side of the malicious OT protocol.
	 */
	public void run() {
		//Run OT extension for each bucket.
		for (int bucketId = 0; bucketId < numBuckets; bucketId++) {
			//Generate random boolean input for the original indices.
			CircuitInput y1 = CircuitInput.randomInput(originalLabels); // This remains hidden
			//Transform the random input to extended inputs.
			CircuitInput y1Extended = matrix.transformInput(y1, primitives.getSecureRandom());
			
			//Set the originsl inputs to all circuits in this bucket.
			for (int j = 0; j < bucketSize; j++) {
				buckets.getBundle(bucketId, j).setY1(y1);
			}
			//Run OT extension on the extended keys.
			runOtExtensionTransfer(y1Extended, bucketId);
		}
	}
	
	/**
	 * Creates the input object to the OT malicious and executes the OT protocol.
	 * @param otInput Contains the input for each input wire.
	 * @param bucketId The index of the bucket to work on.
	 */
	private void runOtExtensionTransfer(CircuitInput otInput, int bucketId) {
		//The sigma input for the OT is the boolean input for the circuit.
		byte[] sigmaArr = otInput.asByteArray();
		int elementSize = 8 * bucketSize * (keySize + hashSize); // Size of each received "x", in bits.
		
		//Create the input object using the sigma array and size of each x.
		OTBatchRInput input = new OTExtensionGeneralRInput(sigmaArr, elementSize);
		
		//Execute the OT protocol.
		OTBatchROutput out = maliciousOtReceiver.transfer(null, input);
		
		//In case the output is not in the expected type, throw an exception.
		if (!(out instanceof OTOnByteArrayROutput)) {
			throw new CheatAttemptException("unexpected output type");
		}
		byte[] output = ((OTOnByteArrayROutput) out).getXSigma();
		
		//Get the Y1 extended garbled keys.
		ArrayList<byte[]> receivedKeysY1Extended = breakOtOutputArray(output, bucketId); 
		
		//Set each circuit in this bucket with the received garbled keys.
		for (int j = 0; j < bucketSize; j++) {
			buckets.getBundle(bucketId, j).setY1ExtendedInputKeys(receivedKeysY1Extended.get(j));
		}
	}

	/**
	 * Breaks the output from the OT in to parts. Each part is the garbled Y1 extended key.
	 * @param output The output of the malicious OT extension protocol.
	 * @param bucketId The index of the bucket to use.
	 * @return The garbled output.
	 * @throws CheatAttemptException In case the given output was not verified using the commitment.
	 */
	private ArrayList<byte[]> breakOtOutputArray(byte[] output, int bucketId) throws CheatAttemptException {
		
		//Will hold the garbled input of each input wire.
		ArrayList<byte[]> receivedKeys = new ArrayList<byte[]>();
		for (int j = 0; j < bucketSize; j++) {
			receivedKeys.add(new byte[m*keySize]);
		}
		
		int pos = 0;
		//For each wire in the transformed input,
		for (int i = 0; i < m; i++) {
			//For each circuit in the bucket,
			for (int j = 0; j < bucketSize; j++) {
				byte[] key = new byte[keySize];
				byte[] r = new byte[hashSize];
				
				//Get from the output the key and random value.
				System.arraycopy(output, pos, key, 0, keySize);
				pos += keySize;
				System.arraycopy(output, pos, r, 0, hashSize);
				pos += hashSize;
				
				//Create decommitment object from the key and random.
				CmtCDecommitmentMessage decom = new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), key);		
				//Get the commitment of the Y1 extended keys of this circuit
				CommitmentBundle commitments = buckets.getBundle(bucketId, j).getCommitmentsY1Extended();
				
				// verify the commitment. 
				//In case the commitment was not verified, throw a cheat exception.
				if ((null == cmtReceiver.verifyDecommitment(commitments.getCommitment(i, 0), decom)) && 
						(null == cmtReceiver.verifyDecommitment(commitments.getCommitment(i, 1), decom)) ) {
					throw new CheatAttemptException("decommitment failed! for i = " + i + " and j = " + j);
				}
				
				//In case the commitment was verified, create a SecretKey from the key array.
				SecretKey kSigma = new SecretKeySpec(key, "");
				//Put the created secret key in the receivedKeys map.
				//receivedKeys.get(j).put(i, kSigma);
				System.arraycopy(kSigma.getEncoded(), 0, receivedKeys.get(j), i*keySize, keySize);
			}
		}
		return receivedKeys;
	}
}
