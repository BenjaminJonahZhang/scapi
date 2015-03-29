package edu.biu.protocols.yao.offlineOnline.primitives;

import java.io.Serializable;

import edu.biu.scapi.interactiveMidProtocols.ByteArrayRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashDecommitmentMessage;

/**
 * This package gathering together some objects that should be sent over the offline protocol. <p>
 * 
 * In order to be as fast as we can, we send a group of thing instead of every one of them alone.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class DecommitmentsPackage implements Serializable {

	private static final long serialVersionUID = -4322129102937001979L;
	
	int hashSize;						//Size of the output of the hash function, in bytes.
	int keySize;						//Size of each key, in bytes.
	int inputSize;						//Size of the input, in bytes.
	int s;								//Security parameter.
	
	/**
	 * The following arguments related to the decommitments: masks, commitments on different wires, ids, etc.
	 */
	private byte[] idCommitmentsX;
	private byte[] idCommitmentsR;
	private byte[] maskCommitmentsX;
	private byte[] maskCommitmentsR;
	private byte[] x;
	private byte[] r;
	private byte[] diffDecommitmentsX;
	private byte[] diffDecommitmentsR;
	
	/**
	 * A constructor that sets the given size parameters and allocate space for the decommitments arrays.
	 * @param numCircuits number of circuits to decommit on.
	 * @param hashSize Size of the output of the hash function, in bytes.
	 * @param keySize Size of each key, in bytes.
	 * @param inputSize Size of the input, in bytes.
	 * @param s Security parameter.
	 */
	public DecommitmentsPackage(int numCircuits, int hashSize, int keySize, int inputSize, int s){
		this.hashSize = hashSize;
		this.keySize = keySize;
		this.inputSize = inputSize;
		this.s = s;
		
		idCommitmentsX = new byte[numCircuits*hashSize];
		idCommitmentsR = new byte[numCircuits*hashSize];
		maskCommitmentsX = new byte[numCircuits*keySize];
		maskCommitmentsR = new byte[numCircuits*hashSize];
		x = new byte[numCircuits*inputSize];
		r = new byte[numCircuits*inputSize*s];
		diffDecommitmentsX = new byte[numCircuits*2*s*inputSize];
		diffDecommitmentsR = new byte[numCircuits*2*s*inputSize];
	}
	
	/**
	 * Returns a MaskDecommitment of the given index.
	 * @param i The index of the mask decommitment that should be returned.
	 * @return The CmtCDecommitmentMessage object related to the given index.
	 */
	public CmtCDecommitmentMessage getMaskDecommitment(int i) {
		//Copy the matching r and x of the requested mask decommitment.
		byte[] r = new byte[hashSize];
		byte[] x = new byte[keySize];
		System.arraycopy(maskCommitmentsR, i*hashSize, r, 0, hashSize);
		System.arraycopy(maskCommitmentsX, i*keySize, x, 0, keySize);
				
		//Create and return a CmtCDecommitmentMessage from the copied x, r.
		return new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), x);
	}
	
	/**
	 * Sets the maskDecommitments of the given index.
	 * @param i The index of the decommitment.
	 * @param maskCommitments The decommitment to set.
	 */
	public void setMaskDecommitment(int i, CmtCDecommitmentMessage maskCommitments) {
		//Copy the decommitment's values to the class members.
		System.arraycopy((byte[]) maskCommitments.getX(), 0, this.maskCommitmentsX, i*keySize, keySize);
		System.arraycopy(((ByteArrayRandomValue)maskCommitments.getR()).getR(), 0, this.maskCommitmentsR, i*hashSize, hashSize);
	}
	
	/**
	 * Returns a IDDecommitment of the given index.
	 * @param i The index of the id decommitment that should be returned.
	 * @return The CmtCDecommitmentMessage object related to the given index.
	 */
	public CmtCDecommitmentMessage getIdDecommitment(int i) {
		//Copy the matching r and x of the requested id decommitment.
		byte[] r = new byte[hashSize];
		byte[] x = new byte[hashSize];
		System.arraycopy(idCommitmentsR, i*hashSize, r, 0, hashSize);
		System.arraycopy(idCommitmentsX, i*hashSize, x, 0, hashSize);
				
		//Create and return a CmtCDecommitmentMessage from the copied x, r.
		return new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), x);
	}
	
	/**
	 * Sets the IDDecommitments of the given index.
	 * @param i The index of the decommitment.
	 * @param maskCommitments The decommitment to set.
	 */
	public void setIdDecommitment(int i, CmtCDecommitmentMessage idCommitments) {
		//Copy the decommitment's values to the class members.
		System.arraycopy((byte[]) idCommitments.getX(), 0, this.idCommitmentsX, i*hashSize, hashSize);
		System.arraycopy(((ByteArrayRandomValue)idCommitments.getR()).getR(), 0, this.idCommitmentsR, i*hashSize, hashSize);
	}

	/**
	 * Sets the X_k value of the diference decommitment.
	 * @param k The index of x.
	 * @param x The value.
	 */
	public void setX(int k, byte[] x) {
		System.arraycopy(x, 0, this.x, k*inputSize, inputSize);
	}
	
	/**
	 * 
	 * Returns the X_i value of the diference decommitment.
	 * @param i The index of the x value that should be returned.
	 */
	public byte[] getX(int i){
		//Copy the requested value and return it.
		byte[] x = new byte[inputSize];
		System.arraycopy(this.x, i*inputSize, x, 0, inputSize);
		return x;
	}
	
	/**
	 * Sets the R_k value of the diference decommitment.
	 * @param k The index of x.
	 * @param xr The random value.
	 */
	public void setR(int k, byte[] r) {
		System.arraycopy(r, 0, this.r, k*inputSize*s, inputSize*s);
	}
	
	/**
	 * Returns the R_i random value of the diference decommitment.
	 * @param i The index of the r value that should be returned.
	 */
	public byte[] getR(int k){
		//Copy the requested value and return it.
		byte[] r = new byte[inputSize*s];
		System.arraycopy(this.r,  k*inputSize*s, r, 0, inputSize*s);
		return r;
	}
	
	/**
	 * Returned the difference commitment ino the given index.
	 * @param i The index of the difference commitment that should be returned.
	 * @param size The size of the decommitment objects to return.
	 * @return Array of size [size] of CmtCDecommitmentMessage objects.
	 */
	public CmtCDecommitmentMessage[] getDiffDecommitment(int i, int size) {
		//Allocate a new array in the given size.
		CmtCDecommitmentMessage[] decommitments = new CmtCDecommitmentMessage[size];
		//Copy each CmtCDecommitmentMessage to its place.
		for (int k=0; k<size; k++){
			byte[] x = new byte[inputSize];
			byte[] r = new byte[hashSize];
			System.arraycopy(diffDecommitmentsX, i*2*s*inputSize+k*inputSize, x, 0, inputSize);
			System.arraycopy(diffDecommitmentsR, i*2*s*hashSize+k*hashSize, r, 0, hashSize);
			decommitments[k] = new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), x);
		}
		//Return the created array.
		return decommitments;
	}
	
	/**
	 * Sets the given difference decommitment array.
	 * @param i The index of the array.
	 * @param diffDecommitments The objects to set.
	 */
	public void setDiffDecommitments(int i, CmtCDecommitmentMessage[] diffDecommitments) {
		//Copy each CmtCDecommitmentMessage to its place in the class member.
		for (int k=0; k<diffDecommitments.length; k++){
			System.arraycopy((byte[]) diffDecommitments[k].getX(), 0, diffDecommitmentsX, i*2*s*inputSize+k*inputSize, inputSize);
			System.arraycopy(((ByteArrayRandomValue)diffDecommitments[k].getR()).getR(), 0, diffDecommitmentsR, i*2*s*hashSize+k*hashSize, hashSize);
		}
	}
}
