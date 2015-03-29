package edu.biu.protocols.CommitmentWithZkProofOfDifference;

import java.io.Serializable;

import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;

/**
 * This class represents one commitment in the difference protocol. <p>
 * Each commitment contains commitment message on the random value r and the xor of r and the message x. <P>
 * It also contain the decommitments of the above commitments.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class SCom implements Serializable {
	private static final long serialVersionUID = -7504265307494851925L;
	/*
	 *  This class should be immutable so all the fields are final.
	 */
	
	private final CmtCCommitmentMsg c0;				//commitment on x xor r.
	private final CmtCCommitmentMsg c1;				//commitment on  r.		
	private final CmtCDecommitmentMessage d0;		//decommitment on x xor r.
	private final CmtCDecommitmentMessage d1;		//decommitment on r.
	
	/**
	 * A constructor that computes the commitment and decommitment messages of x xor r and r.
	 * @param committer Used to commit and decommit the values.
	 * @param x The actual value to commit on.
	 * @param r The random value used to commit.
	 * @param id The first id to use in the commitment.
	 * @throws CommitValueException if the given committer cannot commit on a byte[].
	 */
	public SCom(CmtCommitter committer, byte[] x, byte[] r, long id) throws CommitValueException {
		//Check that the length of the given arrays are equal.
		if (x.length != r.length) {
			throw new IllegalArgumentException();
		}
		
		//Xor x and r.
		byte[] xXorR = new byte[x.length];
		for (int i = 0; i < xXorR.length; i++) {
			xXorR[i] = (byte) (x[i] ^ r[i]);
		}
		
		//Convert the byte[] into a commit value.
		CmtCommitValue v0 = committer.generateCommitValue(xXorR);
		CmtCommitValue v1 = committer.generateCommitValue(r);
		
		//Get the commitment messages of r and x^r.
		c0 = committer.generateCommitmentMsg(v0, id);
		c1 = committer.generateCommitmentMsg(v1, id + 1);
		
		//Get the decommitment messages of r and x^r.
		d0 = committer.generateDecommitmentMsg(c0.getId());
		d1 = committer.generateDecommitmentMsg(c1.getId());
	}
	
	/**
	 * Returns the commitment message of x^r.
	 */
	public CmtCCommitmentMsg getC0() {
		return c0;
	}
	
	/**
	 * Returns the commitment message of r.
	 */
	public CmtCCommitmentMsg getC1() {
		return c1;
	}
	
	/**
	 * Returns the decommitment message of r or x^r according to the given index.
	 * @param i Indicates which decommitment to return.
	 */
	public CmtCDecommitmentMessage getDecom(int i) {
		//If i==0, return the decommitment on x^r.
		//Else, return the decommitment on r.
		return (i == 0) ? d0 : d1;
	}
}
