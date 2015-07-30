package edu.biu.protocols.yao.offlineOnline.primitives;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.protocols.CommitmentWithZkProofOfDifference.DifferenceCommitmentCommitterBundle;
import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastCircuitCreationValues;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledTablesHolder;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;

/**
 * A bundle is a struct that holds a garbled circuit along with all of the circuit's parameters. <p>
 * 
 * These parameters are the input and output keys, translation table, masks, extended keys, commitments on the keys and more. <P>
 * 
 * The bundle is used during the offline and the online phases of the protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class Bundle implements Serializable {
	private static final long serialVersionUID = -6856276544764216868L;
	
	/**
	 * This is an inner class that builds the Bundle.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
	 *
	 */
	public static class Builder {
		private byte[] seed;
		
		private FastGarbledBooleanCircuit garbledCircuit;	// The underlying garbled circuit.
		private FastCircuitCreationValues wireValues;		// Output from the garble function.

		//Masks that are used in the protocol.
		private byte[] placementMask;
		private byte[] commitmentMask;

		//Indices of x, y1 extended, y2 and output wires.
		private int[] inputLabelsX;
		private int[] inputLabelsY1Extended;
		private int[] inputLabelsY2;
		private int[] outputLabels;

		//Additional keys besides the above wires' indices.
		private byte[] inputWiresX;
		private byte[] inputWiresY1Extended;
		private byte[] inputWiresY2;

		//Commitments on the keys.
		private CommitmentBundle commitmentsX;
		private CommitmentBundle commitmentsY1Extended;
		private CommitmentBundle commitmentsY2;
		private CmtCCommitmentMsg commitment;
		private CmtCDecommitmentMessage decommit;

		private SecretKey secret;

		private final int keySize;	//Size of each key, in bytes.
		
		/**
		 * A constructor that sets the given seed and keySize.
		 */
		public Builder(byte[] seed, int keySize) {
			this.seed = seed;
			this.secret = null;
			this.keySize = keySize;
		}
		
		/**
		 * Sets the circuit and its values.
		 * @return The builder that contains these arguments.
		 */
		public Builder circuit(FastGarbledBooleanCircuit garbledCircuit, FastCircuitCreationValues wireValues) {
			this.garbledCircuit = garbledCircuit;
			this.wireValues = wireValues;
			return this;
		}
		
		/**
		 * Sets the masks.
		 * @return The builder that contains these arguments.
		 */
		public Builder masks(byte[] placementMask, byte[] commitmentMask) {
			this.placementMask = placementMask;
			this.commitmentMask = commitmentMask;
			return this;
		}
		
		/**
		 * Sets the wire's indices.
		 * @return The builder that contains these arguments.
		 */
		public Builder labels(int[] inputLabelsX, int[] inputLabelsY1Extended, int[] inputLabelsY2, int[] outputLabels) {
			this.inputLabelsX = inputLabelsX;
			this.inputLabelsY1Extended = inputLabelsY1Extended;
			this.inputLabelsY2 = inputLabelsY2;
			this.outputLabels = outputLabels;
			return this;
		}
		
		/**
		 * Sets the wire's keys.
		 * @return The builder that contains these arguments.
		 */
		public Builder wires(byte[] inputWiresX, byte[] inputWiresY1Extended, byte[] inputWiresY2) {
			this.inputWiresX = inputWiresX;
			this.inputWiresY1Extended = inputWiresY1Extended;
			this.inputWiresY2 = inputWiresY2;
			return this;
		}
		
		/**
		 * Sets the commitments on the keys.
		 * @return The builder that contains these arguments.
		 */
		public Builder commitments(CommitmentBundle commitmentsX, CommitmentBundle commitmentsY1Extended, CommitmentBundle commitmentsY2, CmtCCommitmentMsg commitment, CmtCDecommitmentMessage decommit) {
			this.commitmentsX = commitmentsX;
			this.commitmentsY1Extended = commitmentsY1Extended;
			this.commitmentsY2 = commitmentsY2;
			this.commitment = commitment;
			this.decommit = decommit;
			return this;
		}

		/**
		 * Sets the secret.
		 * @return The builder that contains the secret.
		 */
		public Builder secret(SecretKey secret) {
			this.secret = secret;
			return this;
		}
		
		/**
		 * Builds a new Bundle using this Builder.
		 * @return The created Bundle.
		 */
		public Bundle build() {
			return new Bundle(this);
		}
	}
	
	
	private byte[] seed;
	private GarbledTablesHolder garbledTables;  	// The underlying garbled circuit.
	private final byte[] translationTable;			// Output from the garble function.
	
	//Masks that are used in the protocol.
	private byte[] placementMask;
	private byte[] commitmentMask;
	
	//Indices of x, y1 extended, y2 and output wires.
	private int[] inputLabelsX;
	private int[] inputLabelsY1Extended;
	private int[] inputLabelsY2;
	private int[] outputLabels;
	
	//Additional keys for the above wires' indices.
	private final byte[] inputWiresX;
	private final byte[] inputWiresY1Extended;
	private final byte[] inputWiresY2;
	private byte[] outputWires;
	
	//Commitments on the keys.
	private CommitmentBundle commitmentsX;
	private CommitmentBundle commitmentsY1Extended;
	private CommitmentBundle commitmentsY2;
	
	private SecretKey secret;

	private DifferenceCommitmentCommitterBundle diffCommitments;
	
	private int keySize;	//Size of each key, in bytes.
	
	private CmtCCommitmentMsg commitment;
	private CmtCDecommitmentMessage decommit;
	
	/**
	 * A constructor that gets a builder and sets the inner parameters using the builder.
	 */
	private Bundle(Builder builder) {
		this.seed = builder.seed;
		
		this.garbledTables = builder.garbledCircuit.getGarbledTables();
		this.translationTable = builder.garbledCircuit.getTranslationTable();

		this.placementMask = builder.placementMask;
		this.commitmentMask = builder.commitmentMask;

		this.inputLabelsX = builder.inputLabelsX;
		this.inputLabelsY1Extended = builder.inputLabelsY1Extended;
		this.inputLabelsY2 = builder.inputLabelsY2;
		this.outputLabels = builder.outputLabels;

		this.inputWiresX = builder.inputWiresX;
		this.inputWiresY1Extended = builder.inputWiresY1Extended;
		this.inputWiresY2 = builder.inputWiresY2;
		this.outputWires = builder.wireValues.getAllOutputWireValues();

		this.commitmentsX = builder.commitmentsX;
		this.commitmentsY1Extended = builder.commitmentsY1Extended;
		this.commitmentsY2 = builder.commitmentsY2;
		this.commitment = builder.commitment;
		this.decommit = builder.decommit;
		
		this.secret = builder.secret;
		
		this.keySize = builder.keySize;
	}
	
	public byte[] getSeed() {
		return seed;
	}
	
	public GarbledTablesHolder getGarbledTables() {
		GarbledTablesHolder temp = garbledTables;
		garbledTables = null;
		return temp;
	}

	public byte[] getTranslationTable() {
		return translationTable;
	}
	
	public byte[] getPlacementMask() {
		return placementMask;
	}
	
	public byte[] getCommitmentMask() {
		return commitmentMask;
	}
	
	public int[] getInputLabelsX() {
		return inputLabelsX;
	}

	public int[] getInputLabelsY1Extended() {
		return inputLabelsY1Extended;
	}

	public int[] getInputLabelsY2() {
		return inputLabelsY2;
	}

	public int[] getOutputLabels() {
		return outputLabels;
	}

	public byte[] getInputWiresX() {
		return inputWiresX;
	}

	public byte[] getInputWiresY1Extended() {
		return inputWiresY1Extended;
	}
	
	public SecretKey getProbeResistantWire(int wireIndex, int sigma) {
		Preconditions.checkBinary(sigma);
		return new SecretKeySpec(inputWiresY1Extended, (wireIndex*2+sigma)*keySize, keySize, "");
	}

	public byte[] getInputWiresY2() {
		return inputWiresY2;
	}
	
	public byte[] getOutputWires() {
		return outputWires;
	}
	
	public CommitmentBundle getCommitmentsX() {
		return commitmentsX;
	}

	public CommitmentBundle getCommitmentsY1Extended() {
		return commitmentsY1Extended;
	}
	
	public CommitmentBundle getCommitmentsY2() {
		return commitmentsY2;
	}

	public CmtCCommitmentMsg getCommitmentsOutputKeys() {
		return commitment;
	}
	
	public CmtCDecommitmentMessage getDecommitmentsOutputKeys() {
		return decommit;
	}

	/**
	 * Put in the commitment package the commitments on X, Y1Extended, Y2 and ouptut keys.
	 * @param pack CommitmentsPackage that should be filled with the commitments.
	 */
	public void getCommitments(CommitmentsPackage pack)  {
		pack.setCommitmentsX(commitmentsX.getCommitments(), commitmentsX.getCommitmentsIds());
		pack.setCommitmentsY1Extended(commitmentsY1Extended.getCommitments(), commitmentsY1Extended.getCommitmentsIds());
		pack.setCommitmentsY2(commitmentsY2.getCommitments(), commitmentsY2.getCommitmentsIds());
		pack.setCommitmentsOutputKeys(commitment);
	}

	public void setDifferenceCommitmentBundle(DifferenceCommitmentCommitterBundle bundle) {
		this.diffCommitments = bundle; 
	}
	
	public DifferenceCommitmentCommitterBundle getDifferenceCommitmentBundle() {
		return diffCommitments;
	}
	
	public SecretKey getSecret() {
		return secret;
	}
	

	/**
	 * This function overrides the function from the Serializable interface because we want only part of the 
	 * members to be written to file.
	 * @param out
	 * @throws IOException
	 */
	private void writeObject(ObjectOutputStream out) throws IOException{
		out.writeObject(seed);
		out.writeObject(placementMask);
		out.writeObject(commitmentMask);
		
		out.writeObject(inputLabelsX);
		out.writeObject(inputLabelsY1Extended);
		out.writeObject(inputLabelsY2);
		out.writeObject(outputLabels);
		
		out.writeObject(outputWires);
		
		out.writeObject(commitmentsX);
		out.writeObject(commitmentsY1Extended);
		out.writeObject(commitmentsY2);
		out.writeObject(commitment);
		out.writeObject(decommit);
		
		out.writeObject(secret);
		
		out.writeObject(diffCommitments);
		
		out.writeInt(keySize);
	}
		
	/**
	 * This function overrides the function from the Serializable interface because only some of members should be read from the file.
	 * @param out
	 * @throws IOException
	 */
	private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException{
		seed = (byte[]) in.readObject();
		placementMask = (byte[]) in.readObject();
		commitmentMask = (byte[]) in.readObject();
		
		inputLabelsX = (int[]) in.readObject();
		  
		inputLabelsY1Extended = (int[]) in.readObject();
		inputLabelsY2 = (int[]) in.readObject();
		outputLabels = (int[]) in.readObject();
		
		outputWires = (byte[]) in.readObject();
		
		commitmentsX = (CommitmentBundle) in.readObject();
		commitmentsY1Extended = (CommitmentBundle) in.readObject();
		commitmentsY2 = (CommitmentBundle) in.readObject();
		commitment = (CmtCCommitmentMsg) in.readObject();
		decommit = (CmtCDecommitmentMessage) in.readObject();
		
		secret = (SecretKey) in.readObject();
		
		diffCommitments = (DifferenceCommitmentCommitterBundle) in.readObject();
		
		keySize = in.readInt();
	}
	
}
