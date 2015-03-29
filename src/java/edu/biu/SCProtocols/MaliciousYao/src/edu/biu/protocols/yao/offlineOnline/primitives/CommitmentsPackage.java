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
	
	public CmtCCommitmentMsg[][] getCommitmentsX() {
		//Create and return a CmtCCommitmentMsg[][] from the commitmentsX and commitmentsXIds members.
		int size = commitmentsX.length/2/cmtSize;
		CmtSimpleHashCommitmentMessage[][] coms = new CmtSimpleHashCommitmentMessage[size][];
		for (int k=0; k<size; k++){
			CmtSimpleHashCommitmentMessage[] innerComs = new CmtSimpleHashCommitmentMessage[2];
			for (int i=0; i<2; i++){
				byte[] commitment = new byte[cmtSize];
				System.arraycopy(commitmentsX, k*2*cmtSize+i*cmtSize, commitment, 0, cmtSize);
				innerComs[i] = new CmtSimpleHashCommitmentMessage(commitment, commitmentsXIds[k*2+i]);
			}
			coms[k] = innerComs;
		}
		return coms;
		
	}

	public void setCommitmentsX(CmtCCommitmentMsg[][] commitmentsX) {
		//Set the given commitmentsX in the commitmentsX and commitmentsXIds members.
		this.commitmentsX = new byte[commitmentsX.length*2*cmtSize];
		this.commitmentsXIds = new long[commitmentsX.length*2];
		for (int i=0; i<commitmentsX.length; i++){
			for (int k=0; k<2; k++){
				System.arraycopy(((CmtSimpleHashCommitmentMessage)commitmentsX[i][k]).getCommitment(), 0, this.commitmentsX, i*2*cmtSize+k*cmtSize, cmtSize);
				commitmentsXIds[i*2+k] = commitmentsX[i][k].getId();
			}
		}
	}
	
	public CmtCCommitmentMsg[][] getCommitmentsY1Extended() {
		//Create and return a CmtCCommitmentMsg[][] from the commitmentsY1Extended and commitmentsY1ExtendedIds members.
		int size = commitmentsY1Extended.length/2/cmtSize;
		CmtSimpleHashCommitmentMessage[][] coms = new CmtSimpleHashCommitmentMessage[size][];
		for (int k=0; k<size; k++){
			CmtSimpleHashCommitmentMessage[] innerComs = new CmtSimpleHashCommitmentMessage[2];
			for (int i=0; i<2; i++){
				byte[] commitment = new byte[cmtSize];
				System.arraycopy(commitmentsY1Extended, k*2*cmtSize+i*cmtSize, commitment, 0, cmtSize);
				innerComs[i] = new CmtSimpleHashCommitmentMessage(commitment, commitmentsY1ExtendedIds[k*2+i]);
			}
			coms[k] = innerComs;
		}
		return coms;
	}

	public void setCommitmentsY1Extended(CmtCCommitmentMsg[][] commitmentsY1Extended) {
		//Set the given commitmentsX in the commitmentsY1Extended and commitmentsY1ExtendedIds members.
		this.commitmentsY1Extended = new byte[commitmentsY1Extended.length*2*cmtSize];
		this.commitmentsY1ExtendedIds = new long[commitmentsY1Extended.length*2];
		for (int i=0; i<commitmentsY1Extended.length; i++){
			for (int k=0; k<2; k++){
				System.arraycopy(((CmtSimpleHashCommitmentMessage)commitmentsY1Extended[i][k]).getCommitment(), 0, this.commitmentsY1Extended, i*2*cmtSize+k*cmtSize, cmtSize);
				commitmentsY1ExtendedIds[i*2+k] = commitmentsY1Extended[i][k].getId();
			}
		}
	}

	public CmtCCommitmentMsg[][] getCommitmentsY2() {
		//Create and return a CmtCCommitmentMsg[][] from the commitmentsY2 and commitmentsY2Ids members.
		int size = commitmentsY2.length/2/cmtSize;
		CmtSimpleHashCommitmentMessage[][] coms = new CmtSimpleHashCommitmentMessage[size][];
		for (int k=0; k<size; k++){
			CmtSimpleHashCommitmentMessage[] innerComs = new CmtSimpleHashCommitmentMessage[2];
			for (int i=0; i<2; i++){
				byte[] commitment = new byte[cmtSize];
				System.arraycopy(commitmentsY2, k*2*cmtSize+i*cmtSize, commitment, 0, cmtSize);
				innerComs[i] = new CmtSimpleHashCommitmentMessage(commitment, commitmentsY2Ids[k*2+i]);
			}
			coms[k] = innerComs;
		}
		return coms;
	}

	public void setCommitmentsY2(CmtCCommitmentMsg[][] commitmentsY2) {
		//Set the given commitmentsX in the commitmentsY2 and commitmentsY2Ids members.
		this.commitmentsY2 = new byte[commitmentsY2.length*2*cmtSize];
		this.commitmentsY2Ids = new long[commitmentsY2.length*2];
		for (int i=0; i<commitmentsY2.length; i++){
			for (int k=0; k<2; k++){
				System.arraycopy(((CmtSimpleHashCommitmentMessage)commitmentsY2[i][k]).getCommitment(), 0, this.commitmentsY2, i*2*cmtSize+k*cmtSize, cmtSize);
				commitmentsY2Ids[i*2+k] = commitmentsY2[i][k].getId();
			}
		}
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
