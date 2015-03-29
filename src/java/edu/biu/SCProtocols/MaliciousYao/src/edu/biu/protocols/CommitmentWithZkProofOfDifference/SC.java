package edu.biu.protocols.CommitmentWithZkProofOfDifference;

import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;

/**
 * This class holds the special commitment objects of the difference protocol. <p>
 * This protocol is used in the input consistency check, and reveals the xor of both committed values 
 * without revealing the committed values themselves.<p>
 * 
 * Each commitment object contains a pair of commitments and pair of related decommitments. 
 * 
 * The protocol has multiple commitments according to the security parameter. This class holds all paires of commitments.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class SC implements Serializable {
	private static final long serialVersionUID = -7151204939683931482L;
	private final int n;				//Size of the committed value, in bytes.
	private final int s;				//Security parameter.
	private long commitmentId;			//The id of the commitment object. This is given in the constructor and increased during the creation of the commitments.
										//After creating all commitment objects, it will contain the next available id for the next commitments.
	private byte[][] r;					//Random values used in the commitment.
	private SCom[] commitments;			//List of commitment pairs.
	
	/**
	 * A constructor that sets the given parameters.
	 * @param committer The commitment protocol to use.
	 * @param x The actual committed value.
	 * @param id The id of the commitment object. Will be increased during the creation of the commitments.
	 * After creating all commitment objects, it will contain the next available id for the next commitments.
	 * @param s Security parameter. The number of commitment pairs to create.
	 * @param random Source of randomnes to use.
	 */
	public SC(CmtCommitter committer, byte[] x, long id, int s, SecureRandom random) {
		//Set the parameters.
		this.n = x.length;
		this.s = s;
		this.commitmentId = id;
		
		//Allocate space for the random values and commitments.
		this.r = new byte[s][];
		this.commitments = new SCom[s];
		
		//Create each commitment pair, s times.
		for (int i = 0; i < s; i++) {
			//generate random string.
			r[i] = getRandomString(n, random);
			//Create pair of commitments.
			try {
				commitments[i] = new SCom(committer, x, r[i], commitmentId);
			} catch (CommitValueException e) {
				throw new IllegalStateException(e);
			}
			//Increase the id by 2, since two commitments were already created.
			commitmentId += 2;
		}
	}
	
	/**
	 * A constructor that sets the given parameters.
	 * @param committer The commitment protocol to use.
	 * @param x The actual committed value.
	 * @param id The id of the commitment object. Will be increased during the creation of the commitments.
	 * After creating all commitment objects, it will contain the next available id for the next commitments.
	 * @param s Security parameter. The number of commitment pairs to create.
	 */
	public SC(CmtCommitter committer, byte[] x, long id, int s) {
		//Call the other constructor with a new secure random.
		this(committer, x, id, s, new SecureRandom());
	}
	
	/**
	 * Returns random array where each cell contains 0/1 value.
	 * @param n The size of the required array.
	 * @param random Used to generate the random values.
	 */
	private byte[] getRandomString(int n, SecureRandom random) {
		//Create the array.
		byte[] randomString = new byte[n];
		
		//Put in each cell 0/1.
		for (int i = 0; i < randomString.length; i++) {
			randomString[i] = (byte) random.nextInt(2);
		}
		return randomString;
	}
	
	/**
	 * Returns an array of commitment that contains all commitments objects from all pairs.
	 */
	public CmtCCommitmentMsg[] getCommitments() {
		//Create a long array of commitments.
		CmtCCommitmentMsg[] messages = new CmtCCommitmentMsg[s*2];
		
		//Get each pair of commitments and put the commitments in the big array.
		for (int i = 0; i < s; i++) {
			messages[2*i] = commitments[i].getC0();
			messages[2*i+1] = commitments[i].getC1();
		}
		
		return messages;
	}
	
	/**
	 * Returns an array of decommitment that contains all decommitments objects from all pairs.
	 */
	public CmtCDecommitmentMessage[] getDecommitments() {
		//Create a long array of decommitments.
		CmtCDecommitmentMessage[] messages = new CmtCDecommitmentMessage[2*s];
		
		//Get each pair of decommitments and put the decommitments in the big array.
		for (int i = 0; i < s; i++) {
			messages[i*2] = commitments[i].getDecom(0); 
			messages[i*2 + 1] = commitments[i].getDecom(1); 
		}
		
		return messages;
	}
	
	/**
	 * returns the sigma decommitment from pair number i.
	 * @param i The index of the commitment pair to get the decommitment from.
	 * @param sigma Indicates which decommitment to return. The first of the second.
	 */
	public CmtCDecommitmentMessage getDecom(int i, int sigma) {
		//Get pair i and return the decommitment in place sigma.
		return commitments[i].getDecom(sigma);
	}
	
	/**
	 * Returns the random value that placed in index i.
	 * @param i The index of the random value to return.
	 */
	public byte[] getR(int i) {
		return r[i];
	}
	
	/**
	 * Return a big array that contain all random values.
	 */
	public byte[] getR() {
		//Allocate enough space for all random values.
		int size = r[0].length;
		byte[] allR = new byte[r.length*size];
		
		//Copy each random value to the big array.
		for (int i=0; i<r.length; i++){
			System.arraycopy(r[i], 0, allR, i*size, size);
		}
		return allR;
	}
	
	/**
	 * Returns the id after creation of all commitments. <p>
	 * The id now contain the next available id that can be used for the next commitment.
	 */
	public long getNextAvailableCommitmentId() {
		return commitmentId;
	}
}
