package edu.biu.protocols.yao.offlineOnline.subroutines;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Set;

import edu.biu.protocols.CommitmentWithZkProofOfDifference.CmtWithDifferenceCommitter;
import edu.biu.protocols.CommitmentWithZkProofOfDifference.DifferenceCommitmentCommitterBundle;
import edu.biu.protocols.yao.common.LogTimer;
import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketMapping;
import edu.biu.protocols.yao.offlineOnline.primitives.Bundle;
import edu.biu.protocols.yao.offlineOnline.primitives.BundleBuilder;
import edu.biu.protocols.yao.offlineOnline.primitives.CommitmentsPackage;
import edu.biu.protocols.yao.offlineOnline.primitives.DecommitmentsPackage;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.CutAndChooseSelection;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashReceiver;

/**
 * This is the Cut And Choose prover used in the protocol. <p>
 * 
 * The cut and choose paradigm is an important building block in the offline/online Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CutAndChooseProver {
	
	/**
	 * The following attributes are needed to the prover execution.
	 */
	private final ExecutionParameters execution;		//Contains parameters regarding the execution. 
	private final CryptoPrimitives primitives;			//Contains primitives to use in the protocol.
	private final Channel[] channels;					// The channel that communicates between the parties.
	private final BundleBuilder[] bundleBuilders;		// Contains the circuit parameters used to build the circuit.
	private final int numCircuits;						
	private final CmtSimpleHashCommitter cmtSender;		//Used to commit and decommit during the protocol.
	private final CmtReceiver cmtReceiver;				//Used to receive the commitment and decommitment from the cut and choose verifier. 
	
	private CmtWithDifferenceCommitter diffProtocol;	
	private Bundle[] circuitBundles;					//Contains the garbled circuit.				
	private CmtRCommitPhaseOutput selectionCommitment;	//Commitment of the selection. Received from the cut and choose verifier. 
	private CmtRCommitPhaseOutput mappingCommitment;	//Commitment of the mapping. Received from the cut and choose verifier. 
	
	private CutAndChooseSelection selection;			//The cut and choose selection. Received from the cut and choose verifier after verifying the commitment.
	private BucketMapping bucketMapping;				//The mapping of the circuits to bundles. Received from the cut and choose verifier after verifying the commitment.
	private BucketList<Bundle> buckets;					//List of buckets containing the circuits according to the above mapping.
	
	/**
	 * Constructor that sets the parameters and creates the commitment objects.
	 * @param execution Contains parameters regarding the execution. 
	 * @param primitives Contains primitives to use in the protocol.
	 * @param channel The channel that communicates between the parties.
	 * @param bundleBuilders Contains the circuit parameters and used to build the circuit.
	 */
	public CutAndChooseProver(ExecutionParameters execution, CryptoPrimitives primitives, Channel[] channels, BundleBuilder[] bundleBuilders) {
		this.execution = execution;
		this.primitives = primitives;
		this.channels = channels;
		this.bundleBuilders = bundleBuilders;
		this.numCircuits = execution.numCircuits();
		//Create the commitment objects.
		this.cmtSender = new CmtSimpleHashCommitter(channels[0], primitives.getCryptographicHash(), primitives.getSecureRandom(), primitives.getCryptographicHash().getHashedMsgSize());
		this.cmtReceiver = new CmtSimpleHashReceiver(channels[0], primitives.getCryptographicHash(), primitives.getCryptographicHash().getHashedMsgSize());
		this.circuitBundles = new Bundle[numCircuits];
		
		// Bucket allocation.
		this.buckets = null;
		this.bucketMapping = null;
	}
	
	/**
	 * Runs the prover execution.
	 * 
	 * Pseudo code:
	 * 
	 * 1. Garble the circuits
	 * 2. Receive commitment to cut and choose
	 * 3. Send the garbled circuits
	 * 4. Send commitments on the keys
	 * 5. Receive cut and choose challenge
	 * 6. prove the checked circuits
	 * 7. Put circuits in buckets
	 * 8. Prove correctness of placement mask
	 * 
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	public void run() throws IOException, CheatAttemptException {
		LogTimer timer = new LogTimer("constructGarbledCircuitBundles");
		try {
			//Prepare the garbled circuit, commitment and other parameters needed by the protocol.
			constructGarbledCircuitBundles();
			timer.stop();
			
			//Send to the verifier all garbled circuits.
			//timer.reset("sendGarbledCircuits");
			//sendGarbledCircuits();
			//timer.stop();
			
			//Receive the commitments of the circuits selection and mapping.
			timer.reset("receiveCommitmentToCutAndChoose");
			receiveCommitmentToCutAndChoose();
			timer.stop();
			
			//Generate and send to the verifier the commitments needed by the protocol (on keys, masks, seed, etc).
			timer.reset("sendCommitments");
			sendCommitments();
			timer.stop();
			
			//Receive from the verifier the decommitment of the circuit selection and mapping.
			timer.reset("receiveCutAndChooseChallenge");
			receiveCutAndChooseChallenge();
			timer.stop();
			
			//Prove the checked circuits by sending to the verifier the decommitments of the seeds, masks, keys of the checked circuits.
			timer.reset("proveCheckCircuits");
			proveCheckCircuits();
			timer.stop();
			
			//Put all evaluated circuits in buckets according to the received mapping.
			timer.reset("putCircuitsInBuckets");
			putCircuitsInBuckets();
			timer.stop();
			
			//Prove the placement masks by sending the decommitments of the diff protocol.
			timer.reset("proveCorrectnessOfPlacementMasks");
			proveCorrectnessOfPlacementMasks();
			timer.stop();
		} catch (ClassNotFoundException e) {
			throw new IOException(e);
		}
	}
	
	/**
	 * Returns the buckets that include the evaluated circuits.
	 */
	public BucketList<Bundle> getBuckets() {
		//In case the buckets were not created yet, create them.
		if (null == buckets) {
			putCircuitsInBuckets();
		}
		//Return the filled buckets.
		return buckets;
	}
	
	/**
	 * Garbles each circuit, then commit on its keys.
	 * @throws IOException 
	 */
	private void constructGarbledCircuitBundles() throws IOException {
		//Get the number of threads to use in the protocol.
		int numOfThreads = primitives.getNumOfThreads();
		System.out.println("building garbled circuit bundle for " + numCircuits + " circuits...");
		
		//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
		if (numOfThreads > 0){
			
			ConstructThread[] threads = new ConstructThread[numOfThreads];
			//Calculate the number of circuit in each thread and the remaining.
			int numCircuitsPerThread = numCircuits / numOfThreads;
			int remain = numCircuits % numOfThreads;
			//Create the threads and assign to each one the appropriate circuits.
			//The last thread gets also the remaining circuits.
			for (int j = 0; j < numOfThreads; j++) {
				if ((j != numOfThreads-1) || (remain == 0)){
					threads[j] = new ConstructThread(j, j*numCircuitsPerThread, (j+1)*numCircuitsPerThread);
				} else{
					threads[j] = new ConstructThread(j, j*numCircuitsPerThread, (j+1)*numCircuitsPerThread + remain);
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
				buildCircuit(j, 0);
			}
		}
	}
	
	/**
	 * Inner thread class that construct the circuits in a separate thread.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
	 *
	 */
	private class ConstructThread extends Thread{
		
		private int from;	// The first circuit in the circuit list that should be created.
		private int to;		// The last circuit in the circuit list that should be created.
		private int i;		// The index of the thread.
		
		/**
		 * Constructor that sets the parameters.
		 * @param i The index of the thread.
		 * @param from The first circuit in the circuit list that should be created.
		 * @param to The last circuit in the circuit list that should be created.
		 */
		ConstructThread(int i, int from, int to){
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
					buildCircuit(j, i);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
			}
		}
	}
	
	/**
	 * Garble the circuit in the given index j using the bundle builder of the given index i.
	 * @param j The index in the circuit list where the circuit that should be garbled is placed. 
	 * @param i The index in the bundleBuilders list where the bundle builder that should be used is placed.
	 * @throws IOException 
	 */
	private void buildCircuit(int j, int i) throws IOException {
		// Build a garbled circuit bundle with a randomly picked seed of size 160 bits.
		if (j % 50 == 0) {
			System.out.println("building garbled circuit bundle for circuit j = " + j);
		}
		
		circuitBundles[j] = bundleBuilders[i].build(20);
		channels[i].send(circuitBundles[j].getGarbledTables());
		channels[i].send(circuitBundles[j].getTranslationTable());
	}
	
	/**
	 * Receives from the cut and choose verifier the commitment on the cut and choose selection and the mapping of the circuit into buckets. 
	 * @throws ClassNotFoundException 
	 * @throws IOException
	 */
	private void receiveCommitmentToCutAndChoose() throws ClassNotFoundException, IOException {
		selectionCommitment = cmtReceiver.receiveCommitment();
		mappingCommitment = cmtReceiver.receiveCommitment();
	}
	
//	/**
//	 * Sends to the cut and choose verifier the garbled circuits. 
//	 * This is done by sending the garbled tables and translation tables of the circuits.
//	 * @throws IOException
//	 */
//	private void sendGarbledCircuits() throws IOException {
//		//For each circuit, send the garbled table and translation table.
//		for (int j = 0; j < circuitBundles.length; j++) {
//			channel.send(circuitBundles[j].getGarbledTables());
//			channel.send(circuitBundles[j].getTranslationTable());
//		}
//	}
	
	/**
	 * Generate and send the cut and choose commitments. 
	 * The commitments are on the seeds, masks, keys of every circuit bundles and also the commitments on B[0], ..., B[j-1].
	 * @throws IOException In case there is a problem during the communication.
	 */
	private void sendCommitments() throws IOException,CheatAttemptException{
		//Send a commitment package for each circuit bundle.
		for (int j = 0; j < circuitBundles.length; j++) {
			//Create the commitment package.
			CommitmentsPackage cmtPackage = new CommitmentsPackage(primitives.getCryptographicHash().getHashedMsgSize(), primitives.getStatisticalParameter());
			
			//Generate the commitment messages on the seed and mask and put them in the commitment package.
			CmtCommitValue commitValueSeed = null;
			CmtCommitValue commitValueCommitmentMask = null;
			try {
				commitValueSeed = cmtSender.generateCommitValue(circuitBundles[j].getSeed());
				commitValueCommitmentMask = cmtSender.generateCommitValue(circuitBundles[j].getCommitmentMask());
			} catch (CommitValueException e) {
				throw new IllegalStateException(e);
			}
			cmtPackage.setSeedCmt(cmtSender.generateCommitmentMsg(commitValueSeed, 2*j)); // COMMIT_ID_SEED
			cmtPackage.setMaskCmt(cmtSender.generateCommitmentMsg(commitValueCommitmentMask, 2*j+1)); // COMMIT_ID_COMMITMENT_MASK
			
			//Set the commitments on the keys in the commitment package.
			circuitBundles[j].getCommitments(cmtPackage);
			
			//Send the commitment package.
			channels[0].send(cmtPackage);
		}
		
		//Get the placement masks of each circuit bundle.
		byte[][] placementMasks = new byte[numCircuits][];
		for (int j = 0; j < numCircuits; j++) {
			placementMasks[j] = circuitBundles[j].getPlacementMask();
		}
		CommitmentsPackage cmtPackage = new CommitmentsPackage(primitives.getCryptographicHash().getHashedMsgSize(), primitives.getStatisticalParameter());
		// TODO: at the moment the randomness of the CommitWithDifferenceProtocol does not come from the seed.
		diffProtocol = new CmtWithDifferenceCommitter(placementMasks, numCircuits, primitives.getStatisticalParameter(), channels[0], primitives.getSecureRandom(), primitives.getCryptographicHash());
		diffProtocol.setup(); // receive commitments to K and W, and receive ccSelection encrypted
		cmtPackage.setDiffCommitments(diffProtocol.getCommitments()); // send commitments to B[0], ..., B[j-1]
		
		for (int j = 0; j < circuitBundles.length; j++) {
			circuitBundles[j].setDifferenceCommitmentBundle(diffProtocol.getBundle(j));
		}
		
		//Send the commitment package.
		channels[0].send(cmtPackage);
	}

	/**
	 * Receive Decommitments of the cut and choose selection and the circuits mapping. 
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private void receiveCutAndChooseChallenge() throws CheatAttemptException, IOException   {
		byte[] ccSelection;
		byte[] bucketMappingSeed;
		//Receive the cut and choose selection and the circuits mapping.
		try {
			ccSelection = cmtReceiver.generateBytesFromCommitValue(cmtReceiver.receiveDecommitment(selectionCommitment.getCommitmentId()));
			bucketMappingSeed = cmtReceiver.generateBytesFromCommitValue(cmtReceiver.receiveDecommitment(mappingCommitment.getCommitmentId()));
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		} catch (CommitValueException e) {
			throw new IllegalStateException(e);
		}
		//Create the selection object using the received decommitment.
		selection = new CutAndChooseSelection(ccSelection);
		//Create the mapping object from the received selection and mapping.
		bucketMapping = new BucketMapping(selection.evalCircuits(), bucketMappingSeed, execution.numberOfExecutions(), execution.bucketSize());
	}
	
	/**
	 * Prove the checked circuits by decommiting on the seed, mask and keys of each selected circuit.
	 * @throws IOException In case there was a problem in the communication.
	 */
	private void proveCheckCircuits() throws IOException {
		//Get the indices of the checked circuits.
		Set<Integer> select = selection.checkCircuits();
		
		//Create the package that contains the decommitments.
		DecommitmentsPackage provePack = null;
		try {
			provePack = new DecommitmentsPackage(select.size(), primitives.getCryptographicHash().getHashedMsgSize(), primitives.getMultiKeyEncryptionScheme().getCipherSize(), execution.getBooleanCircuit().getNumberOfInputs(1), primitives.getStatisticalParameter());
		} catch (NoSuchPartyException e) {
			// Should not occur.
		}
		int counter = 0;
		//Put in the decommitment package the decommitments of the seed, mask, and keys of each checked circuit and also the difference decommitments.
		for (int j : select) {
			provePack.setIdDecommitment(counter, cmtSender.generateDecommitmentMsg(2*j)); // COMMIT_ID_SEED
			provePack.setMaskDecommitment(counter, cmtSender.generateDecommitmentMsg(2*j+1)); // COMMIT_ID_COMMITMENT_MASK
			diffProtocol.getDecommit(j, counter, provePack);
			counter++;
		}
		
		//Send the decommitments to the cut and choose verifier.
		channels[0].send(provePack);
	}
	
	/**
	 * Put the evaluated circuits in buckets, according to the mapping algorithm received from the cut and choose verifier.
	 */
	private void putCircuitsInBuckets() {
		Preconditions.checkNotNull(bucketMapping);
		
		//Create the bucket list and add each evaluated circuit.
		buckets = new BucketList<Bundle>(execution, bucketMapping);
		for (int j : selection.evalCircuits()) {
			buckets.add(circuitBundles[j], j);
		}
	}
	
	/**
	 * Run the verify stage of the diff protocol for each evaluate circuits.
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private void proveCorrectnessOfPlacementMasks() throws CheatAttemptException, IOException  {
		Preconditions.checkNotNull(buckets);
		
		// For each bucket, run the verify stage of the diff protocol (for eval circuits).
		for (int i = 0; i < buckets.size(); i++) {
			ArrayList<DifferenceCommitmentCommitterBundle> commitBucket = new ArrayList<DifferenceCommitmentCommitterBundle>();
			ArrayList<Bundle> bucket = buckets.getBucket(i);
			for (int j = 0; j < bucket.size(); j++) {
				commitBucket.add(bucket.get(j).getDifferenceCommitmentBundle());
			}
			
			try {
				diffProtocol.proveDifferencesBetweenMasks(commitBucket);
			} catch (ClassNotFoundException e) {
				throw new IOException(e);
			}
		}
	}
}
