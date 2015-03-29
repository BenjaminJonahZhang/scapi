package edu.biu.protocols.CommitmentWithZkProofOfDifference;

import java.io.Serializable;

/**
 * This message is sent during the input consistency protocol in the offline phase. <P>
 * 
 * This message gather some small messages in order to make the sending more efficient, since sending small messages is less 
 * efficient than a big message.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
class ProveDiff implements Serializable {
	
	private static final long serialVersionUID = 2257659781066816566L;
	
	private byte[] committedDifference;		//
	private byte[] delta;
	int n;									//The total number of circuits. (checked + eval)
	int s;									//Security parameter. Indicates how much commitments pairs will be.
	
	/**
	 * A constructor that sets the parameters.
	 * @param numCircuits number of secrets.
	 * @param n The total number of circuits. (checked + eval)
	 * @param s Security parameter.
	 */
	ProveDiff(int numCircuits, int n, int s){
		committedDifference = new byte[numCircuits*n];
		delta = new byte[numCircuits*2*s*n];
		this.n = n;
		this.s = s;
	}

	/**
	 * Returns the committed difference from the given index in the committedDifference class member.
	 * @param i The index of the committed difference to return.
	 */
	public byte[] getCommittedDifference(int i) {
		//Create an array to hold the result.
		byte[] ret = new byte[n];
		//Copy the necessary bytes into the created array.
		System.arraycopy(committedDifference, i*n, ret, 0, n);
		return ret;
	}

	/**
	 * Sets the given committed difference in the given index in the committedDifference inline member.
	 * @param i The index where to put the given committedDifference.
	 * @param committedDifference The value to put.
	 */
	public void setCommittedDifference(int i, byte[] committedDifference) {
		//Copy the given value to the big class member.
		System.arraycopy(committedDifference, 0, this.committedDifference, i*n, n);
	}
	
	/**
	 * Returns the delta array from of the given index in the delta class member.
	 * @param i The index to take the delta from.
	 */
	public byte[] getDelta(int i) {
		//Create an array to hold the delta.
		byte[] delta = new byte[2*s*n];
		//Copy the necessary bytes into the created array.
		System.arraycopy(this.delta, i*2*s*n, delta, 0, 2*s*n);
		return delta;
	}

	/**
	 * Sets the given delta in the given index in the delta inline member.
	 * @param i The index where to put the given delta.
	 * @param delta The value to put.
	 */
	public void setDelta(int i, byte[] delta) {
		//Copy the given value to the big class member.
		System.arraycopy(delta, 0, this.delta, i*2*s*n, 2*s*n);
	}
}
