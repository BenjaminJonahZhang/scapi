package edu.biu.protocols.yao.offlineOnline.primitives;

import java.io.Serializable;

import edu.biu.scapi.interactiveMidProtocols.ByteArrayRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashDecommitmentMessage;

/**
 * This package is being filled in the online protocol by p1 and sent to p2. <p>
 * 
 * This way, there is only one send instead of sending each member alone; This saves time.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class EvaluationPackage implements Serializable {
	private static final long serialVersionUID = 1077274355216014487L;
	
	//The following members needed in the online protocol.
	
	//Masks.
	private byte[] placementMasks;
	private byte[] commitmentMasks;
	private byte[] maskOnD2Input;
	
	//Decommitments on the keys.
	private byte[] decommitmentsY2InputKeysX;
	private byte[] decommitmentsY2InputKeysR;
	private byte[] decommitmentsXInputKeysX;
	private byte[] decommitmentsXInputKeysR;
	
	private byte[] decommitmentsOutputKeysX;
	private byte[] decommitmentsOutputKeysR;
	
	//Proof of cheating.
	private byte[] xoredProofOfCheating;
	private byte[] hashedProofOfCheating;
	private byte[] proofOfCheating;

	/*
	 * Getters and setters for each class member.
	 */
	
	
	public void setCommitmentMask(byte[] commitmentMask) {
		this.commitmentMasks = commitmentMask;
	}
	
	public byte[] getCommitmentMask() {
		return commitmentMasks;
	}

	public void setDecommitmentsToY2InputKeys(byte[]x, byte[] r) {
		this.decommitmentsY2InputKeysX = x;
		this.decommitmentsY2InputKeysR = r;
	}

	public void setDecommitmentsToXInputKeys(byte[] x, byte[] r) {
		this.decommitmentsXInputKeysX = x;
		this.decommitmentsXInputKeysR = r;
	}
	
	public void setDecommitmentsToOutputKeys(byte[] x, byte[] r) {
		this.decommitmentsOutputKeysX = x;
		this.decommitmentsOutputKeysR = r;
	}
	
	/**
	 * Returns Decommitment to Y2 input keys, according to the given circuit id and the index.
	 * @param circuitId The circuit that the requested decommitment belongs.
	 * @param index The index of the y2 input wire that the decommitment belongs.
	 * @param numWires number of input wires.
	 * @param keySize The size of each key, in bytes.
	 * @param hashSize The size of the decommitment, in bytes.
	 */
	public CmtCDecommitmentMessage getDecommitmentToY2InputKey(int circuitId, int index, int numWires, int keySize, int hashSize) {
		byte[] x = new byte[keySize];
		System.arraycopy(decommitmentsY2InputKeysX, keySize*(circuitId*numWires + index), x, 0, keySize);
		byte[] r = new byte[hashSize];
		System.arraycopy(decommitmentsY2InputKeysR, hashSize*(circuitId*numWires + index), r, 0, hashSize);
				
		return new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), x);
	}
	
	/**
	 * Returns Decommitment to X input keys, according to the given circuit id and the index.
	 * @param circuitId The circuit that the requested decommitment belongs.
	 * @param index The index of the x input wire that the decommitment belongs.
	 * @param numWires number of input wires.
	 * @param keySize The size of each key, in bytes.
	 * @param hashSize The size of the decommitment, in bytes.
	 */
	public CmtCDecommitmentMessage getDecommitmentToXInputKey(int circuitId, int index, int numWires, int keySize, int hashSize) {
		byte[] x = new byte[keySize];
		System.arraycopy(decommitmentsXInputKeysX, keySize*(circuitId* numWires + index), x, 0, keySize);
		byte[] r = new byte[hashSize];
		System.arraycopy(decommitmentsXInputKeysR, hashSize*(circuitId*numWires + index), r, 0, hashSize);
				
		return new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), x);
	}
	
	/**
	 * Returns Decommitment to output key, according to the given circuit id.
	 * @param circuitId The circuit that the requested decommitment belongs.
	 * @param numWires number of output wires.
	 * @param keySize The size of each key, in bytes.
	 * @param hashSize The size of the decommitment, in bytes.
	 */
	public CmtCDecommitmentMessage getDecommitmentToOutputKey(int circuitId, int numWires, int keySize, int hashSize) {
		byte[] x = new byte[keySize*2*numWires];
		System.arraycopy(decommitmentsOutputKeysX, keySize*circuitId*numWires*2, x, 0, keySize*2*numWires);
		byte[] r = new byte[hashSize];
		System.arraycopy(decommitmentsOutputKeysR, hashSize*circuitId, r, 0, hashSize);
		
		return new CmtSimpleHashDecommitmentMessage(new ByteArrayRandomValue(r), x);
	}
	
	public void addMaskOnD2(byte[] maskOnD2Input) {
		this.maskOnD2Input = maskOnD2Input;
	}
	
	public byte[] getMaskOnD2() {
		return maskOnD2Input;
	}

	public void setPlacementMask(byte[] placementMask) {
		this.placementMasks = placementMask;
	}
	
	public byte[] getPlacementMask() {
		return placementMasks;
	}

	public void setXoredProofOfCheating(byte[] proofParts) {
		this.xoredProofOfCheating = proofParts;
	}
	
	/**
	 * Returns the xored proof, according to the given circuit id, index and sigma.
	 * @param wireIndex The index of the wire that the proof belongs.
	 * @param circuitId The circuit that the requested proof belongs.
	 * @param sigma Indicates which proof to return (there are two proofs for each wire.)
	 * @param numCircuits number of circuits.
	 * @param keySize The size of each key, in bytes.
	 */
	public byte[] getXoredProof(int wireIndex, int circuitId, int sigma, int numCircuits, int keySize) {
		byte[] bytes = new byte[keySize];
		System.arraycopy(xoredProofOfCheating, keySize*(wireIndex*numCircuits*2 + circuitId*2 + sigma), bytes, 0, keySize);
		return bytes;
	}

	public void setHashedProofOfCheating(byte[] hashedProof) {
		this.hashedProofOfCheating = hashedProof;
	}
	
	public byte[] getHashedProof() {
		return hashedProofOfCheating;
	}

	public void addProofOfCheating(byte[] proofOfCheating) {
		this.proofOfCheating = proofOfCheating;
	}

	public byte[] getProofOfCheating() {
		return proofOfCheating;
	}
}
