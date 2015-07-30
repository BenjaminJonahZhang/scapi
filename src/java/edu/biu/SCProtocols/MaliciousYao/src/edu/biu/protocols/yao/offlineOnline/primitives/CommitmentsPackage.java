package edu.biu.protocols.yao.offlineOnline.primitives;

import java.io.Serializable;

import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashCommitmentMessage;

/**
 * This package gathering together some objects that should be sent over the offline protocol. <p>
 * 
 * In order to be as fast as we can, we send a group of thing instead of every one of them alone.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CommitmentsPackage implements Serializable {
	
	private static final long serialVersionUID = 4528918351966920697L;
	
	int cmtSize = 20;				//Size of every commitment, in bytes.
	int s;							//Security parameter.
	
	/**
	 * The following arguments related to the commitments: masks, commitments on different wires, ids, etc.
	 */
	private byte[] seedCmt;
	private long seedIds;
	private byte[] maskCmt;
	private long maskIds;
	private byte[] commitmentsX;
	private long[] commitmentsXIds;
	private byte[] commitmentsY1Extended;
	private long[] commitmentsY1ExtendedIds;
	private byte[] commitmentsY2;
	private long[] commitmentsY2Ids;
	private byte[] commitmentsOutputKeys;
	private byte[] diffCommitments;
	private long[] diffCommitmentsIds;
	
	/**
	 * A constructor that sets the given parameters.
	 * @param cmtSize Size of every commitment, in bytes.
	 * @param s Security parameter.
	 */
	public CommitmentsPackage(int cmtSize, int s){
		this.cmtSize = cmtSize;
		this.s = s;
	}
	
	/*
	 * Setters and getters for each class member.
	 * We set each one of them in a row way, in order to avoid additional information that java adds on every array.
	 * This way the sent amount of data is small and the time to send is the minimum.
	 */
	public void setSeedCmt(CmtCCommitmentMsg seedCommitment) {
		seedCmt = ((CmtSimpleHashCommitmentMessage)seedCommitment).getCommitment();
		seedIds = seedCommitment.getId();
	}
	
	public CmtCCommitmentMsg getSeedCmt() {
		return new CmtSimpleHashCommitmentMessage(seedCmt, seedIds);
	}
	
	public void setMaskCmt(CmtCCommitmentMsg maskCommitment) {
		this.maskCmt = ((CmtSimpleHashCommitmentMessage)maskCommitment).getCommitment();
		maskIds = maskCommitment.getId();
	}
	
	public CmtCCommitmentMsg getMaskCmt() {
		return new CmtSimpleHashCommitmentMessage(maskCmt, maskIds);
	}
	
	public byte[] getCommitmentsX() {
		return commitmentsX;
		
	}
	
	public long[] getCommitmentXIds(){
		return commitmentsXIds;
	}

	public void setCommitmentsX(byte[] commitmentsX, long[] commitmentsXIds) {
		
		this.commitmentsX = commitmentsX;
		this.commitmentsXIds = commitmentsXIds;
	}
	
	public byte[] getCommitmentsY1Extended() {
		
		return commitmentsY1Extended;
	}
	
	public long[] getCommitmentY1ExtendedIds(){
		return commitmentsY1ExtendedIds;
	}


	public void setCommitmentsY1Extended(byte[] commitmentsY1Extended, long[] commitmentsY1ExtendedIds) {
		
		this.commitmentsY1Extended = commitmentsY1Extended;
		this.commitmentsY1ExtendedIds = commitmentsY1ExtendedIds;
	}

	public byte[] getCommitmentsY2() {
		
		return commitmentsY2;
	}
	
	public long[] getCommitmentY2Ids(){
		return commitmentsY2Ids;
	}

	public void setCommitmentsY2(byte[] commitmentsY2, long[] commitmentsY2Ids) {
		
		this.commitmentsY2 = commitmentsY2;
		this.commitmentsY2Ids = commitmentsY2Ids;
	}

	public CmtCCommitmentMsg getCommitmentsOutputKeys() {
		//Create and return a CmtCCommitmentMsg from the commitmentsOutputKeys.
		return new CmtSimpleHashCommitmentMessage(commitmentsOutputKeys, 0);
	}

	public void setCommitmentsOutputKeys(CmtCCommitmentMsg output) {
		//Set the given commitmentsX in the commitmentsOutputKeys and commitmentsOutputKeysIds members.
		this.commitmentsOutputKeys = ((CmtSimpleHashCommitmentMessage)output).getCommitment();
	}

	public CmtCCommitmentMsg[][] getDiffCommitments() {
		//Create and return a CmtCCommitmentMsg[][] from the diffCommitments and diffCommitmentsIds members.
		int size = diffCommitments.length/(2*s)/cmtSize;
		CmtCCommitmentMsg[][] commitments = new CmtCCommitmentMsg[size][];
		for (int k=0; k < size; k++){
			CmtSimpleHashCommitmentMessage[] innerComs = new CmtSimpleHashCommitmentMessage[2*s];
			for (int i=0; i<2*s; i++){
				byte[] commitment = new byte[cmtSize];
				System.arraycopy(diffCommitments, k*s*2*cmtSize+i*cmtSize, commitment, 0, cmtSize);
				innerComs[i] = new CmtSimpleHashCommitmentMessage(commitment, diffCommitmentsIds[k*2*s+i]);
			}
			commitments[k] = innerComs;
		}
		return commitments;
	}

	public void setDiffCommitments(CmtCCommitmentMsg[][] diffCommitments) {
		//Set the given commitmentsX in the diffCommitments and diffCommitmentsIds members.
		this.diffCommitments = new byte[diffCommitments.length*2*s*cmtSize];
		this.diffCommitmentsIds = new long[diffCommitments.length*2*s];
		for (int i=0; i<diffCommitments.length; i++){
			CmtCCommitmentMsg[] com = diffCommitments[i];
			for (int k=0; k<com.length; k++){
				System.arraycopy(((CmtSimpleHashCommitmentMessage)com[k]).getCommitment(), 0, this.diffCommitments, i*s*2*cmtSize+k*cmtSize, cmtSize);
				diffCommitmentsIds[i*2*s+k] = com[k].getId();
			}
		}
	}

}
