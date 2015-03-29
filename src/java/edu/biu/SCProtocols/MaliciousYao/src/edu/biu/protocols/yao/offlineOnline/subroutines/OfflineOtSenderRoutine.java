package edu.biu.protocols.yao.offlineOnline.subroutines;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.protocols.yao.common.KeyUtils;
import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.Bundle;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.interactiveMidProtocols.ByteArrayRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousSender;

/**
 * Runs the sender side of the malicious OT protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class OfflineOtSenderRoutine {
	private final OTExtensionMaliciousSender maliciousOtSender;			// The inner malicious OT sender object.
	private final BucketList<Bundle> buckets;							// Contain the circuits.
	
	/*
	 * Needed lengths.
	 */
	private final int numBuckets;
	private final int bucketSize;
	private final int hashSize;
	private final int keySize;
	private final int m;												// The size of the Y2 extended keys.
	
	/**
	 * A constructor that sets the class members.
	 * @param execution Contains some parameters used in the OT. For example the bucket size.
	 * @param primitives Primitives objects to use during the protocol execution.
	 * @param maliciousOtSender The inner malicious OT sender object.
	 * @param matrix The matrix to convert the original Y1 input to the Y1 extended inputs.
	 * @param buckets Contain the circuits.
	 */
	public OfflineOtSenderRoutine(ExecutionParameters execution, CryptoPrimitives primitives, OTExtensionMaliciousSender maliciousOtSender,
			KProbeResistantMatrix matrix, BucketList<Bundle> buckets) {
		//Sets the parameters.
		this.maliciousOtSender = maliciousOtSender;
		this.buckets = buckets;
		this.numBuckets = execution.numberOfExecutions();
		this.bucketSize = execution.bucketSize();
		this.hashSize = primitives.getCryptographicHash().getHashedMsgSize();
		this.keySize = primitives.getMultiKeyEncryptionScheme().getCipherSize();
		this.m = matrix.getProbeResistantInputSize();
	}

	/**
	 * Runs the sender side of the malicious OT protocol for each bucket.
	 */
	public void run() {
		for (int bucketId = 0; bucketId < numBuckets; bucketId++) {
			runOtExtensionTransfer(bucketId);
		}
	}
	
	/**
	 * Creates the input for the OT sender and executes the OT protocol.
	 * @param bucketId The index of the bucket to work on.
	 */
	private void runOtExtensionTransfer(int bucketId) {
		//Get the garbled inputs of each party.
		byte[] x0Arr = buildInput(bucketId, 0);
		byte[] x1Arr = buildInput(bucketId, 1);
		
		//Create the input for the OT sender.
		OTBatchSInput input = new OTExtensionGeneralSInput(x0Arr, x1Arr, m);
		
		//Execute the OT protocol.
		maliciousOtSender.transfer(null, input);
	}
	
	/**
	 * Returns the garbled input of the given party.
	 * @param bucketId The index of the bucket to work on.
	 * @param b Indicates which party to get the inputs of. 0 for the first party and 1 for the second.
	 */
	private byte[] buildInput(int bucketId, int b) {
		Preconditions.checkBinary(b);
		
		//Allocate space for the input array.
		byte[] inputArr = new byte[m * bucketSize * (keySize + hashSize)];
		int pos = 0;
		
		// For each wire the keys and decommitments for all circuits are grouped together.
		for (int i = 0; i < m; i++) {
			for (int j = 0; j < bucketSize; j++) {
				Bundle bundle = buckets.getBundle(bucketId, j);
				
				//Get the xor of the key and commitment mask.
				SecretKey xorKeyWithCmtMask;
				try {
					xorKeyWithCmtMask = KeyUtils.xorKeys(bundle.getProbeResistantWire(i, b), new SecretKeySpec(bundle.getCommitmentMask(), ""));
				} catch (InvalidInputException e) {
					throw new IllegalStateException();
				}
				byte[] key = xorKeyWithCmtMask.getEncoded();
				
				//Get the random value of the decommitment for this wire.
				CmtCDecommitmentMessage decom = bundle.getCommitmentsY1Extended().getDecommitment(i, b);
				byte[] r = ((ByteArrayRandomValue) decom.getR()).getR();
				
				//Put in the input array the key and random. The receiver will use them to verify the commitments of Y1 extended keys.
				System.arraycopy(key, 0, inputArr, pos, keySize);
				pos += keySize;
				System.arraycopy(r, 0, inputArr, pos, hashSize);
				pos += hashSize;
			}
		}
		
		return inputArr;
	}

}
