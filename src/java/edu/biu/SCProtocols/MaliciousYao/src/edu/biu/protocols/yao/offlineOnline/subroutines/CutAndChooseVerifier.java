package edu.biu.protocols.yao.offlineOnline.subroutines;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import edu.biu.protocols.CommitmentWithZkProofOfDifference.CmtWithDifferenceReceiver;
import edu.biu.protocols.CommitmentWithZkProofOfDifference.DifferenceCommitmentReceiverBundle;
import edu.biu.protocols.yao.common.LogTimer;
import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketMapping;
import edu.biu.protocols.yao.offlineOnline.primitives.Bundle;
import edu.biu.protocols.yao.offlineOnline.primitives.BundleBuilder;
import edu.biu.protocols.yao.offlineOnline.primitives.CheatingRecoveryBundleBuilder;
import edu.biu.protocols.yao.offlineOnline.primitives.CommitmentBundle;
import edu.biu.protocols.yao.offlineOnline.primitives.CommitmentsPackage;
import edu.biu.protocols.yao.offlineOnline.primitives.DecommitmentsPackage;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.primitives.LimitedBundle;
import edu.biu.protocols.yao.primitives.ChooseFractionSelectionBuilder;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.CutAndChooseSelection;
import edu.biu.protocols.yao.primitives.Expector;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledTablesHolder;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashReceiver;

/**
 * This is the Cut And Choose verifier used in the protocol. <p>
 * 
 * The cut and choose paradigm is an important building block in the offline/online Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CutAndChooseVerifier {
	
	/**
	 * The following attributes are needed to the prover execution.
	 */
	
	private static final int COMMIT_ID_CUT_AND_CHOOSE = 1;
	private static final int COMMIT_ID_BUCKET_MAPPING = 2;
	
	private final ExecutionParameters execution;		//Contains parameters regarding the execution. 
	private final CryptoPrimitives primitives;			//Contains primitives to use in the protocol.
	private final Channel[] channels;						// The channel that communicates between the parties.
	private final BundleBuilder bundleBuilder;			// Contains the circuit parameters used to build the circuit.
	private final CutAndChooseSelection selection;		// Indicates for each circuit if it is a checked circuit or evaluated circuit.
	private final BucketMapping bucketMapping;			//The object that used in order to randomly map the circuits into buckets.
	private final byte[] seedMapping;					//Seed to the above mapping algorithm.
	private final int numCircuits;
	private final CmtCommitter cmtSender;				//Used to commit and decommit during the protocol.
	private final CmtSimpleHashReceiver cmtReceiver;	//Used to receive the commitment and decommitment from the cut and choose prover. 
	
	private GarbledTablesHolder[] garbledTables;		//Will hold the garbled table of each circuit.
	private byte[][] translationTables;					//Will hold the translation table of each circuit.
	
	/*
	 * wires' indices.
	 */
	private int[] inputLabelsX;
	private final int[] inputLabelsY1Extended;
	private int[] inputLabelsY2;
	private int[] outputLabels;
	
	/*
	 * Commitment used in the protocol: includes commitments on seeds, masks, keys.
	 */
	private CmtCCommitmentMsg[] commitmentToSeed;
	private CmtCCommitmentMsg[] commitmentToCommitmentMask;
	private CommitmentBundle[] commitmentsX;
	private CommitmentBundle[] commitmentsY1Extended;
	private CommitmentBundle[] commitmentsY2;
	private CmtCCommitmentMsg[] commitmentsOutput;
	private CmtCDecommitmentMessage[] decommitmentsOutput;
	
	//This protocol and its related bundles are used in the input consistency check.
	private DifferenceCommitmentReceiverBundle[] diffCommitments;
	private CmtWithDifferenceReceiver diffProtocol;

	private BucketList<LimitedBundle> buckets;			//Will hold the circuits according to the mapping algorithm.
	
	/**
	 * Constructor that sets the parameters and creates the commitment objects.
	 * @param execution Contains parameters regarding the execution. 
	 * @param primitives Contains primitives to use in the protocol.
	 * @param channel The channel that communicates between the parties.
	 * @param bundleBuilders Contains the circuit parameters and used to build the circuit.
	 * @param matrix Used to transform p1 inputs to the extended inputs. 
	 */
	public CutAndChooseVerifier(ExecutionParameters execution, CryptoPrimitives primitives, Channel[] channels, BundleBuilder bundleBuilder, KProbeResistantMatrix matrix) {
		//Call the other constructor with no input indices.
		this(execution, primitives, channels, bundleBuilder, matrix, null);
	}
	
	/**
	 * Constructor that sets the parameters and creates the commitment objects.
	 * @param execution Contains parameters regarding the execution. 
	 * @param primitives Contains primitives to use in the protocol.
	 * @param channel The channel that communicates between the parties.
	 * @param bundleBuilders Contains the circuit parameters and used to build the circuit.
	 * @param matrix Used to transform p1 inputs to the extended inputs. 
	 * @param inputLabelsY2 The input wires' indices of p2. Sometimes these indices are not the same as in the given circuit.
	 */
	public CutAndChooseVerifier(ExecutionParameters execution, CryptoPrimitives primitives, Channel[] channels, 
			BundleBuilder bundleBuilder, KProbeResistantMatrix matrix, int[] inputLabelsY2) {
		
		//Sets the class member s using the given values.
		this.execution = execution;
		this.primitives = primitives;
		this.channels = channels;
		this.bundleBuilder = bundleBuilder;
		this.numCircuits = execution.numCircuits();
		
		//Do the circuits selection.
		this.selection = selectCutAndChoose();
		
		//DO the circuits mapping.
		this.seedMapping = (new SecureRandom()).generateSeed(20);	//Generate seed for the mapping algorithm.
		this.bucketMapping = new BucketMapping(selection.evalCircuits(), seedMapping, execution.numberOfExecutions(), execution.bucketSize());
		
		//Create the commitment objects.
		this.cmtSender = new CmtSimpleHashCommitter(channels[0], primitives.getCryptographicHash(), primitives.getSecureRandom(), primitives.getCryptographicHash().getHashedMsgSize());
		this.cmtReceiver = new CmtSimpleHashReceiver(channels[0], primitives.getCryptographicHash(), primitives.getCryptographicHash().getHashedMsgSize());
		
		//Get the circuit indices.
		FastGarbledBooleanCircuit gbc = execution.getCircuit(0);
		this.outputLabels = gbc.getOutputWireIndices();
		try {
			this.inputLabelsX = execution.getCircuit(0).getInputWireIndices(1);
			//If the user gave indices, use them. Else, get p2 indices from the circuit.
			//Sometimes these indices are not the same as in the given circuit. In these cases the user should give the inputs. 
			this.inputLabelsY2 = (inputLabelsY2 != null) ? (inputLabelsY2) : gbc.getInputWireIndices(2);
    	} catch (NoSuchPartyException e) {
    		// Should not occur.
    	}
		this.inputLabelsY1Extended = matrix.getProbeResistantLabels();
		
		
		//Create the commitments arrays.
		this.commitmentToSeed = new CmtCCommitmentMsg[numCircuits];
		this.commitmentToCommitmentMask = new CmtCCommitmentMsg[numCircuits];
		this.commitmentsX = new CommitmentBundle[numCircuits];
		this.commitmentsY1Extended = new CommitmentBundle[numCircuits];
		this.commitmentsY2 = new CommitmentBundle[numCircuits];
		this.commitmentsOutput = new CmtCCommitmentMsg[numCircuits];
		this.decommitmentsOutput = new CmtCDecommitmentMessage[numCircuits];
		this.diffCommitments = new DifferenceCommitmentReceiverBundle[numCircuits];
		
	}
	
	/**
	 * Run the verifier execution.
	 * 
	 * Pseudo code:
	 * 
	 * 1. Send to the cut and choose prover the commitments on the circuit selection and mapping.
	 * 2. Receive the garbled circuits
	 * 4. Receive commitments on the keys
	 * 5. Send the cut and choose challenge
	 * 6. verify the checked circuits
	 * 7. Put circuits in buckets
	 * 8. verify correctness of placement mask
	 * 
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	public void run() throws IOException, CheatAttemptException {
		
		//Receive all garbled circuits from the cut and choose prover.
	//	LogTimer timer = new LogTimer("receiveGarbledCircuits");
		receiveGarbledCircuits();
	//	timer.stop();
		//Send the commitments of the circuits selection and mapping.
		//	timer.reset("commitToCutAndChoose");
		commitToCutAndChoose();
	//	timer.stop();
		
		//Receive the commitments needed by the protocol (on keys, masks, seed, etc).
	//	timer.reset("receiveCommitments");
		receiveCommitments();
	//	timer.stop();
		
		//Send to the cut and choose prover the circuit selection and mapping.
	//	timer.reset("revealCutAndChoose");
		revealCutAndChoose();
	//	timer.stop();
		
		//Verify the checked circuits by verifying the commitments of the seeds, masks, keys of the checked circuits.
	//	timer.reset("verifyCheckCircuits");
		verifyCheckCircuits();
	//	timer.stop();
		
		//Put all evaluated circuits in buckets according to the received mapping.
	//	timer.reset("putCircuitsInBuckets");
		putCircuitsInBuckets();
	//	timer.stop();
		
		//Verify the placement masks by verifying the decommitments of the diff protocol.
	//	timer.reset("verifyCorrectnessOfPlacementMasks");
		verifyCorrectnessOfPlacementMasks();
	//	timer.stop();
	}
	
	/**
	 * Returns the buckets that include the evaluated circuits.
	 */
	public BucketList<LimitedBundle> getBuckets() {
		//In case the buckets were not created yet, create them.
		if (null == buckets) {
			putCircuitsInBuckets();
		}
		//Return the filled buckets.
		return buckets;
	}
	
	/**
	 * Put the evaluated circuits in buckets, according to the mapping algorithm received from the cut and choose verifier.
	 */
	private void putCircuitsInBuckets() {
		Preconditions.checkNotNull(bucketMapping);
		
		//Create the bucket list and add each evaluated circuit.
		buckets = new BucketList<LimitedBundle>(execution, bucketMapping);
		for (int j : selection.evalCircuits()) {
			//Create a LimitedBundle from the received garbled table, translation table, wires' indices and commitments.
			LimitedBundle.Builder bundleBuilder = new LimitedBundle.Builder();
			LimitedBundle bundle = bundleBuilder.circuit(garbledTables[j], translationTables[j])
			.labels(inputLabelsX, inputLabelsY1Extended, inputLabelsY2, outputLabels)
			.commitments(commitmentsX[j], commitmentsY1Extended[j], commitmentsY2[j], commitmentsOutput[j], decommitmentsOutput[j], diffCommitments[j])
			.build();
			buckets.add(bundle, j);
		}
	}
	
	/**
	 * Selects the checked circuit and the evaluated circuits.
	 * @return The selection object that contains the circuits selection.
	 */
	private CutAndChooseSelection selectCutAndChoose() {
		//Create the selection object.
		ChooseFractionSelectionBuilder selectionBuilder = new ChooseFractionSelectionBuilder(execution.checkCircuits());
		//Do the actual selection.
		return selectionBuilder.build(execution.numCircuits());
	}
	
	/**
	 * Commits on the circuit selection and the circuit mapping.
	 * @throws IOException In case of a problem during the communication.
	 */
	private void commitToCutAndChoose() throws IOException {
		try {
			cmtSender.commit(cmtSender.generateCommitValue(selection.asByteArray()), COMMIT_ID_CUT_AND_CHOOSE);
			cmtSender.commit(cmtSender.generateCommitValue(seedMapping), COMMIT_ID_BUCKET_MAPPING);
		} catch (CommitValueException e) {
			throw new IOException(e);
		}
	}
	
	/**
	 * Receive the garbled tables and translation table of all circuits.
	 * @throws CheatAttemptException
	 * @throws IOException
	 */
	private void receiveGarbledCircuits() throws CheatAttemptException, IOException {
		
		//Create place to hold all tables.
		garbledTables = new GarbledTablesHolder[numCircuits];
		translationTables = new byte[numCircuits][];
				
		//Get the number of threads to use in the protocol.
		int numOfThreads = primitives.getNumOfThreads();
//		System.out.println("building garbled circuit bundle for " + numCircuits + " circuits...");
		
		//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
		if (numOfThreads > 0){
			
			ReceiveThread[] threads = new ReceiveThread[numOfThreads];
			//Calculate the number of circuit in each thread and the remaining.
			int numCircuitsPerThread = numCircuits / numOfThreads;
			int remain = numCircuits % numOfThreads;
			//Create the threads and assign to each one the appropriate circuits.
			//The last thread gets also the remaining circuits.
			for (int j = 0; j < numOfThreads; j++) {
				if ((j != numOfThreads-1) || (remain == 0)){
					threads[j] = new ReceiveThread(j, j*numCircuitsPerThread, (j+1)*numCircuitsPerThread);
				} else{
					threads[j] = new ReceiveThread(j, j*numCircuitsPerThread, (j+1)*numCircuitsPerThread + remain);
				}
				//Start all threads.
				threads[j].start();
			}
			//Wait until all threads finish their job.
			for (int j = 0; j < numOfThreads; j++) {
				try {
					threads[j].join();
				} catch (InterruptedException e) {
					throw new IllegalStateException();
				}
			}
		//In case no thread should be created, build all the circuits directly.
		} else {
			for (int j = 0; j < numCircuits; j++) {
				receiveCircuit(j, 0);
			}
		}
	}
	
	/**
	 * Inner thread class that construct the circuits in a separate thread.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
	 *
	 */
	private class ReceiveThread extends Thread{
		
		private int from;	// The first circuit in the circuit list that should be created.
		private int to;		// The last circuit in the circuit list that should be created.
		private int i;		// The index of the thread.
		
		/**
		 * Constructor that sets the parameters.
		 * @param i The index of the thread.
		 * @param from The first circuit in the circuit list that should be created.
		 * @param to The last circuit in the circuit list that should be created.
		 */
		ReceiveThread(int i, int from, int to){
			this.i = i;
			this.from = from;
			this.to = to;
		}
		
		/**
		 * Builds the circuits from the start point to the end point in the circuit list.
		 */
		public void run(){
			for (int j = from; j < to; j++) {
				try {
					receiveCircuit(j, i);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
			}
		}
	}
	
	private void receiveCircuit(int j, int i) throws IOException {
		//Initialize the expectors objects to receive the tables. 
		Expector garbledTablesExpector = new Expector(channels[i], GarbledTablesHolder.class);
		Expector translationTableExpector = new Expector(channels[i], byte[].class);
		
		//Receive the garbled and translation tables of each circuit.
		garbledTables[j] = (GarbledTablesHolder) garbledTablesExpector.receive();
		translationTables[j] = (byte[]) translationTableExpector.receive();
		
	}
	
	/**
	 * Receive from the cut and choose prover the commitments (on seeds, masks, keys, etc) of each circuit. 
	 * @throws CheatAttemptException
	 * @throws IOException
	 */
	private void receiveCommitments() throws CheatAttemptException, IOException {
		//Create a new difference protocol.
		diffProtocol = new CmtWithDifferenceReceiver(selection, numCircuits, primitives.getStatisticalParameter(), channels[0], primitives.getSecureRandom(), primitives.getCryptographicHash());
		diffProtocol.setup(); // Send commitments to K and W, and send ccSelection encrypted
		Expector expector = new Expector(channels[0], CommitmentsPackage.class);
		
		//For each circuit, receive the commitments on the seed, mask and keys and put them in the relative commitment array.
		for (int j = 0; j < numCircuits; j++) {
			CommitmentsPackage commitments = (CommitmentsPackage) expector.receive();
			
			commitmentToSeed[j] = commitments.getSeedCmt();
			commitmentToCommitmentMask[j] = commitments.getMaskCmt();
			
			commitmentsX[j] = CommitmentBundle.setCommitments(commitments.getCommitmentsX(), inputLabelsX);
			commitmentsY1Extended[j] = CommitmentBundle.setCommitments(commitments.getCommitmentsY1Extended(), inputLabelsY1Extended);
			commitmentsY2[j] = CommitmentBundle.setCommitments(commitments.getCommitmentsY2(), inputLabelsY2);
			commitmentsOutput[j] = commitments.getCommitmentsOutputKeys();
		}
		//Receive the commitments  of the diff protocol.
		CommitmentsPackage commitments = (CommitmentsPackage) expector.receive();
		
		//Receive commitments to B[0], ..., B[j-1]
		diffProtocol.receiveCommitment(commitments.getDiffCommitments());
		
		for (int j = 0; j < numCircuits; j++) {
			diffCommitments[j] = diffProtocol.getBundle(j);
		}
	}
	
	/**
	 * Send to the cut and choose prover the decommitments on the circuit selection and mapping.
	 * @throws IOException
	 * @throws CheatAttemptException In case of problem during the decommiting.
	 */
	private void revealCutAndChoose() throws IOException, CheatAttemptException {
		try {
			cmtSender.decommit(COMMIT_ID_CUT_AND_CHOOSE);
			cmtSender.decommit(COMMIT_ID_BUCKET_MAPPING);
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		} catch (CommitValueException e) {
			throw new IllegalStateException(e);
		}
	}
	
	/**
	 * Verify the checked circuit by verifying the commitments on the seed, masks and keys.
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private void verifyCheckCircuits() throws IOException, CheatAttemptException {
		//Receive the decommitments.
		Expector expector = new Expector(channels[0], DecommitmentsPackage.class);
		DecommitmentsPackage decommitments = (DecommitmentsPackage) expector.receive();
		int counter = 0;
		//For each checked circuit:
		for (int j : selection.checkCircuits()) {
			
			//Verify the seed and commitment mask.
			byte[] seed = cmtReceiver.generateBytesFromCommitValue(cmtReceiver.verifyDecommitment(commitmentToSeed[j], decommitments.getIdDecommitment(counter)));
			byte[] commitmentMask = cmtReceiver.generateBytesFromCommitValue(cmtReceiver.verifyDecommitment(commitmentToCommitmentMask[j], decommitments.getMaskDecommitment(counter)));
			
			//Build the circuit using the verified seed.
			Bundle circuitBundle = bundleBuilder.build(seed);
			
			//Check that the verified mask is equal to the generated mask.
			if (!Arrays.equals(circuitBundle.getCommitmentMask(), commitmentMask)) {
				throw new CheatAttemptException("decommitment of commitmentMask does not match the decommitted seed!");
			}
			
			if (!checkEquality(circuitBundle.getGarbledTables().toDoubleByteArray(), (garbledTables[j].toDoubleByteArray()))) {
				throw new CheatAttemptException("garbled tables does not match the decommitted seed!");
			}
			
			if (!Arrays.equals(circuitBundle.getTranslationTable(), translationTables[j])) {
				throw new CheatAttemptException("translation tables does not match the decommitted seed!");
			}
			//Verify the keys commitments.
			circuitBundle.getCommitmentsX().verifyCommitmentsAreEqual(commitmentsX[j]);
			//In case this is a cheating recovery circuit, we know the secret and can verify the commitments order.
			// Otherwise we cannot verify.
			if (!(bundleBuilder instanceof CheatingRecoveryBundleBuilder)) {
				circuitBundle.getCommitmentsY1Extended().verifyCommitmentsAreEqual(commitmentsY1Extended[j]);
				circuitBundle.getCommitmentsY2().verifyCommitmentsAreEqual(commitmentsY2[j]);
			}
			verifyCommitmentsAreEqual(commitmentsOutput[j], circuitBundle.getCommitmentsOutputKeys());
			
			//Receive decommitments of the difference protocol.
			diffProtocol.receiveDecommitment(j, counter, decommitments);
			
			counter++;
		}
	}
	
	private boolean checkEquality(byte[][] array1, byte[][] array2) {
		if (array1.length != array2.length){
			return false;
		}
		for (int i=0; i<array1.length; i++){
			if (array1[i].length != array2[i].length){
				return false;
			}
			for (int j=0; j<array1[i].length; j++){
				if (array1[i][j] != array2[i][j]){
					return false;
				}
			}
		}
		
		return true;
			
	}

	/**
	 * Checks that both commitment objects are equal. If they are not equal - throw an exception.
	 * @param m1 The first commitment to check.
	 * @param m2 The second commitment to check.
	 */
	private void verifyCommitmentsAreEqual(CmtCCommitmentMsg m1, CmtCCommitmentMsg m2){
		
		String c1 = m1.toString();
		String c2 = m2.toString();
		if (!c1.equals(c2)) {
			//In case the commitments are different, throw an exception.
			throw new CheatAttemptException(String.format("commitments differ"));
		}
	}

	/**
	 * Run the verify stage of the diff protocol for each evaluate circuits.
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private void verifyCorrectnessOfPlacementMasks() throws IOException, CheatAttemptException {
		Preconditions.checkNotNull(buckets);
		
		// For each bucket, run the verify stage of the diff protocol (for eval circuits).
		for (int i = 0; i < buckets.size(); i++) {
			ArrayList<DifferenceCommitmentReceiverBundle> commitBucket = new ArrayList<DifferenceCommitmentReceiverBundle>();
			ArrayList<LimitedBundle> bucket = buckets.getBucket(i);
			for (int j = 0; j < bucket.size(); j++) {
				commitBucket.add(bucket.get(j).getDifferenceCommitmentBundle());
			}
			
			byte[][] committedDifference = diffProtocol.verifyDifferencesBetweenMasks(commitBucket);
			
			for (int j = 0; j < bucket.size() - 1; j++) {
				bucket.get(j).setPlacementMaskDifference(committedDifference[j]);
			}
		}
	}
}
