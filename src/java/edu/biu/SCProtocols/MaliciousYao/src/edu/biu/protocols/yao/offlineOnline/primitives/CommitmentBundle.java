package edu.biu.protocols.yao.offlineOnline.primitives;

import java.io.Serializable;
import java.util.HashMap;

import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;

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
	
	private final int[] labels;											// Wires' indices.
	private final HashMap<Integer, CmtCCommitmentMsg[]> commitments;	// Commitments on all wires' keys.
	private HashMap<Integer, CmtCDecommitmentMessage[]> decommitments;	// Decommitments on all wires' keys.

	/**
	 * A constructor that sets the given arguments.
	 * @param labels The wires' indices.
	 * @param commitments Commitments on all wires' keys.
	 * @param decommitments Decommitments on all wires' keys.
	 */
	public CommitmentBundle(int[] labels, HashMap<Integer, CmtCCommitmentMsg[]> commitments, HashMap<Integer, CmtCDecommitmentMessage[]> decommitments) {
		this.labels = labels;
		this.commitments = commitments;
		this.decommitments = decommitments;
	}
	
	/**
	 * A constructor that sets the given arguments.
	 * @param labels The wires' indices.
	 * @param commitments Commitments on all wires' keys.
	 */
	public CommitmentBundle(int[] labels, HashMap<Integer, CmtCCommitmentMsg[]> commitments) {
		this(labels, commitments, null);
	}
	
	/**
	 * Returns the wires' indices.
	 */
	public int[] getLabels() {
		return labels;
	}
	
	/**
	 * Returns the commitment that matches the given sigma of the given wire index.
	 * @param wireIndex The index of the wire to get the commitment on.
	 * @param sigma A boolean that indicates which commitment to return.
	 */
	public CmtCCommitmentMsg getCommitment(int wireIndex, int sigma) {
		//Check that the sigma is 0/1.
		Preconditions.checkBinary(sigma);
	
		//Return the commitment that matches the given sigma of the given wire index.
		return commitments.get(labels[wireIndex])[sigma];
		
		
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
		return decommitments.get(labels[wireIndex])[sigma];
		
		
	}
	
	/**
	 * Returns all commitments in a CmtCCommitmentMsg[][] structure.
	 */
	public CmtCCommitmentMsg[][] getCommitments() {
		//Create a CmtCCommitmentMsg[][] structure.
		CmtCCommitmentMsg[][] commitmentsArr = null;
		
		commitmentsArr = new CmtCCommitmentMsg[labels.length][];
		
		//Get both commitments of each wire index and put them in the right place in the two-dimensions array.
		for (int i = 0; i < labels.length; i++) {
			commitmentsArr[i] = commitments.get(labels[i]);
		}
		
		return commitmentsArr;

	}
	
	/**
	 * Set the commitments of the given wires' indices.
	 * @param commitmentsArr two- dimensions array that holds each commitment of each wire's key.
	 * @param labels Indices of the wires.
	 * @return A new created commitment bundle.
	 */
	public static CommitmentBundle setCommitments(CmtCCommitmentMsg[][] commitmentsArr, int[] labels) {
		//Create a new hashmap to hold the commitments.
		HashMap<Integer, CmtCCommitmentMsg[]> commitments = new HashMap<Integer, CmtCCommitmentMsg[]>();
		
		//For each wire index get the commitments and put them in the map.
		for (int i = 0; i < labels.length; i++) {
			CmtCCommitmentMsg[] com = commitmentsArr[i];
			
			commitments.put(labels[i], com);
		}
		
		//Create and return a new CommitmentBundle with the given indices and created map.
		return new CommitmentBundle(labels, commitments);
	}
	
	/**
	 * Verifies that this commitment bundle and the given one are equal.
	 * @param other Another CommitmentBundle to check equality.
	 * @throws CheatAttemptException in case the given bundle is different than this one.
	 */
	public void verifyCommitmentsAreEqual(CommitmentBundle other) throws CheatAttemptException {
		
		//For each wire's index in the labels array:
		for (int i = 0; i < labels.length; i++) {
			//Get the index and the matching commitments.
			int w = labels[i];
			CmtCCommitmentMsg[] com = commitments.get(w);
			//Check that both commitments are equal.
			for (int k = 0; k < 2; k++) {
				String c1 = com[k].toString();
				String c2 = other.getCommitment(i, k).toString();
				if (!c1.equals(c2)) {
					//In case the commitments are different, throw an exception.
					throw new CheatAttemptException(String.format("commitments differ for label=%d and sigma=%d: c1 = %s, c2 = %s", w, k, c1, c2));
				}
			}
		}
	}
}
