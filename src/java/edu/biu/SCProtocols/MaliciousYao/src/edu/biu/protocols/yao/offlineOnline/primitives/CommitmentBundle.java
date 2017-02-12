package edu.biu.protocols.yao.offlineOnline.primitives;

import java.io.Serializable;

import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ByteArrayRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashCommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashDecommitmentMessage;

/**
 * A CommitmentBundle is a struct that holds the parameters pf the commitments on the keys. <P>
 * 
 * These parameters are the commitements of all keys, decommitments and the wires indices. <P>
 * 
 * The bundle is used during the offline and the online phases of the protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CommitmentBundle implements Serializable {
	private static final long serialVersionUID = 8023872699392337021L;
	
//	private CmtCDecommitmentMessage[] decommitments;// Decommitments on all wires' keys.
	
	private byte[] commitments;
	private long[] commitmentIds;
	private byte[] decommitments;
	private byte[] decommitmentRandoms;
	
	int commitmentSize = 20;
	int keySize = 16;
	
	/**
	 * A constructor that sets the given arguments.
	 * @param commitments Commitments on all wires' keys.
	 * @param decommitments Decommitments on all wires' keys.
	 */
	public CommitmentBundle(byte[] commitments, long[] commitmentsIds, byte[] decommitments, byte[] decommitmentRandoms) {
		this.commitments = commitments;
		this.commitmentIds = commitmentsIds;
		this.decommitments = decommitments;
		this.decommitmentRandoms = decommitmentRandoms;
	}
	
	
	/**
	 * A constructor that sets the given arguments.
	 * @param commitments Commitments on all wires' keys.
	 */
	public CommitmentBundle(byte[] commitments, long[] commitmentIds) {
		this(commitments, commitmentIds, null, null);
	}
	
	/**
	 * Returns the commitment that matches the given sigma of the given wire index.
	 * @param wireIndex The index of the wire to get the commitment on.
	 * @param sigma A boolean that indicates which commitment to return.
	 */
	public CmtCCommitmentMsg getCommitment(int wireIndex, int sigma) {
		//Check that the sigma is 0/1.
		Preconditions.checkBinary(sigma);
	
		//Return the commitment that matches the given sigma of the given wire index.\
		byte[] commitment = new byte[commitmentSize];
		System.arraycopy(commitments, wireIndex*2*commitmentSize+sigma*commitmentSize, commitment, 0, commitmentSize);
		return new CmtSimpleHashCommitmentMessage(commitment, commitmentIds[wireIndex*2+sigma]);
		
		
	}
	
	/**
	 * Returns the decommitment that matches the given sigma of the given wire index.
	 * @param wireIndex The index of the wire to get the decommitment on.
	 * @param sigma A boolean that indicates which decommitment to return.
	 */
	public CmtCDecommitmentMessage getDecommitment(int wireIndex, int sigma) {
		//Check that the sigma is 0/1.
		Preconditions.checkBinary(sigma);
		
		//Return the decommitment that matches the given sigma of the given wire index.
		byte[] r = new byte[commitmentSize];
		byte[] x = new byte[keySize];
		System.arraycopy(decommitmentRandoms, wireIndex*2*commitmentSize + sigma*commitmentSize, r, 0, commitmentSize);
		System.arraycopy(decommitments, wireIndex*2*keySize + sigma*keySize, x, 0, keySize);
				
		//Create and return a CmtCDecommitmentMessage from the copied x, r.
		return new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), x);
		//return decommitments[wireIndex *2 + sigma];
		
		
	}
	
	/**
	 * Returns all commitments in a CmtCCommitmentMsg[][] structure.
	 */
	public byte[] getCommitments() {
		//Create a CmtCCommitmentMsg[][] structure.
//		CmtCCommitmentMsg[][] commitmentsArr = null;
//		
//		commitmentsArr = new CmtCCommitmentMsg[labels.length][];
//		
//		//Get both commitments of each wire index and put them in the right place in the two-dimensions array.
//		for (int i = 0; i < labels.length; i++) {
//			commitmentsArr[i] = commitments.get(labels[i]);
//		}
//		
//		return commitmentsArr;
		return commitments;

	}
	
	public long[] getCommitmentsIds(){
		return commitmentIds;
	}
	
	/**
	 * Set the commitments of the given wires' indices.
	 * @param commitmentsArr two- dimensions array that holds each commitment of each wire's key.
	 * @return A new created commitment bundle.
	 */
	public static CommitmentBundle setCommitments(byte[] commitmentsArr, long[] commitmentIds) {
		//Create a new hashmap to hold the commitments.
//		HashMap<Integer, CmtCCommitmentMsg[]> commitments = new HashMap<Integer, CmtCCommitmentMsg[]>();
//		
//		//For each wire index get the commitments and put them in the map.
//		for (int i = 0; i < labels.length; i++) {
//			CmtCCommitmentMsg[] com = commitmentsArr[i];
//			
//			commitments.put(labels[i], com);
//		}
//		
//		//Create and return a new CommitmentBundle with the given indices and created map.
//		return new CommitmentBundle(labels, commitments);
		return new CommitmentBundle(commitmentsArr, commitmentIds);
	}
	
	/**
	 * Verifies that this commitment bundle and the given one are equal.
	 * @param other Another CommitmentBundle to check equality.
	 * @throws CheatAttemptException in case the given bundle is different than this one.
	 */
	public void verifyCommitmentsAreEqual(CommitmentBundle other) throws CheatAttemptException {
		int size = commitmentIds.length/2; 
		//For each wire's index in the labels array:
		for (int i = 0; i < size; i++) {
			//Get the index and the matching commitments.
			//CmtCCommitmentMsg[] com = commitments[i];
			//Check that both commitments are equal.
			for (int k = 0; k < 2; k++) {
				String c1 = getCommitment(i, k).toString();
				String c2 = other.getCommitment(i, k).toString();
				if (!c1.equals(c2)) {
					//In case the commitments are different, throw an exception.
					throw new CheatAttemptException(String.format("commitments differ for index=%d and sigma=%d: c1 = %s, c2 = %s", i, k, c1, c2));
				}
			}
		}
	}
}
