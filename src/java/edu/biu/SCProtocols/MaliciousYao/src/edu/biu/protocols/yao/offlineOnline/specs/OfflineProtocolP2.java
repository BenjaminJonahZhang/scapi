package edu.biu.protocols.yao.offlineOnline.specs;

import java.io.IOException;
import java.util.ArrayList;

import edu.biu.protocols.yao.common.CircuitUtils;
import edu.biu.protocols.yao.common.LogTimer;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.BundleBuilder;
import edu.biu.protocols.yao.offlineOnline.primitives.CheatingRecoveryBundleBuilder;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.primitives.LimitedBundle;
import edu.biu.protocols.yao.offlineOnline.subroutines.CutAndChooseVerifier;
import edu.biu.protocols.yao.offlineOnline.subroutines.OfflineOtReceiverRoutine;
import edu.biu.protocols.yao.primitives.CommunicationConfig;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrixBuilder;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

/**
 * This class represents the second party in the offline phase of Malicious Yao protocol. <P>
 * 
 * The full protocol specification is described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for 
 * Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, page 18 - section E, "The Full Protocol Specification".
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class OfflineProtocolP2 {
	private final ExecutionParameters mainExecution;	// Parameters of the main circuit.
	private final ExecutionParameters crExecution;		// Parameters of the cheating recovery circuit.
	private final CryptoPrimitives primitives;			// Contains the low level instances to use.
	private final Channel[] channels;					// The channels used communicate between the parties.

	private KProbeResistantMatrix mainMatrix;			//The probe-resistant matrix used to extend the main circuit's keys.
	private KProbeResistantMatrix crMatrix;				//The probe-resistant matrix used to extend the cheating recovery circuit's keys.
	
	private BucketList<LimitedBundle> mainBuckets;		//Contain the main circuits.
	private BucketList<LimitedBundle> crBuckets;		//Contain the cheating recovery circuits.
	private OTExtensionMaliciousReceiver maliciousOtReceiver;		//The malicious OT used to transfer the keys.
	
	/**
	 * Constructor that sets the parameters. 
	 * @param mainExecution Parameters of the main circuit.
	 * @param crExecution Parameters of the cheating recovery circuit.
	 * @param primitives Contains the low level instances to use.
	 * @param communication Configuration of communication between parties.
	 */
	public OfflineProtocolP2(ExecutionParameters mainExecution, ExecutionParameters crExecution, CryptoPrimitives primitives, 
			CommunicationConfig communication, OTExtensionMaliciousReceiver maliciousOtReceiver) {
		this.mainExecution = mainExecution;
		this.crExecution = crExecution;
		this.primitives = primitives;
		this.channels = communication.getChannels();		// Get the channel from the communication configuration.
		this.maliciousOtReceiver = maliciousOtReceiver;
	}
	
	/**
	 * Runs the second party in the offline phase of the malicious Yao protocol.
	 */
	public void run() {
		//LogTimer timer = new LogTimer("selecting and sending probe resistant matrices");
		try {
			int crInputSizeY = primitives.getMultiKeyEncryptionScheme().getCipherSize()*8;
			
			// Selecting E and sending it to P1.
			mainMatrix = selectAndSendProbeResistantMatrix(mainExecution);
			// Selecting E' and sending it to P1 (derive the length of the new input from the MES key size - that is the size of proofOfCheating).
			crMatrix = selectAndSendProbeResistantMatrix(crInputSizeY, crExecution.statisticalParameter()); 
			//timer.stop();
			
		//	timer.reset("runCutAndChooseProtocol(AES)");
			//Create the main bundleBuilder from the main circuit.
			//Use the first circuit only because there is no use of thread in this party and therefore, only one circuit is needed.
			BundleBuilder mainBundleBuilder = new BundleBuilder(mainExecution.getCircuit(0), mainMatrix, primitives, channels);
			
			//Run Cut and Choose protocol on the main circuit.
			mainBuckets = runCutAndChooseProtocol(mainExecution, mainMatrix, mainBundleBuilder); 
		//	timer.stop();
			
		//	timer.reset("runCutAndChooseProtocol(CR)");
			//Create the cheating recovery bundleBuilder from the main circuit.
			//Use the first circuit only because there is no use of thread in this party and therefore, only one circuit is needed.
			BundleBuilder crBundleBuilder = new CheatingRecoveryBundleBuilder(crExecution.getCircuit(0), crMatrix, 
					primitives, channels, primitives.getMultiKeyEncryptionScheme().generateKey());
			//Run Cut and Choose protocol on the cheating recovery circuit.
			crBuckets = runCutAndChooseProtocol(crExecution, crMatrix, crBundleBuilder, getSecretSharingLabels(crInputSizeY)); 
		//	timer.stop();
			
		//	timer.reset("runObliviousTransferOnP2Keys(AES)");
			//Run OT on p2 keys of the main circuit.
			runObliviousTransferOnP2Keys(mainExecution, mainMatrix, mainBuckets);
		//	timer.stop();
			
		//	timer.reset("runObliviousTransferOnP2Keys(CR)");
			//Run OT on p2 keys of the cheating recovery circuit.
			runObliviousTransferOnP2Keys(crExecution, crMatrix, crBuckets);
		//	timer.stop();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CheatAttemptException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Returns indices list, from 1 to crInputSizeY.
	 * @param crInputSizeY Number of indices to return.
	 */
	private int[] getSecretSharingLabels(int crInputSizeY) {
		int[] labels = new int[crInputSizeY];
		for (int i = 0; i < crInputSizeY; i++) {
			labels[i] = i+1; // Labels start with "1".
		}
		return labels;
	}

	/**
	 * Returns the list of main circuit's buckets.
	 */
	public BucketList<LimitedBundle> getMainBuckets() {
		return mainBuckets;
	}
	
	/**
	 * Returns the list of cheating recovery circuit's buckets.
	 */
	public BucketList<LimitedBundle> getCheatingRecoveryBuckets() {
		return crBuckets;
	}
	
	/**
	 * Returns the probe resistant matrix related to the main circuit.
	 */
	public KProbeResistantMatrix getMainProbeResistantMatrix() {
		return mainMatrix;
	}
	
	/**
	 * Returns the probe resistant matrix related to the cheating recovery circuit.
	 */
	public KProbeResistantMatrix getCheatingRecoveryProbeResistantMatrix() {
		return crMatrix;
	}
	
	/**
	 * Creates a probe resistant matrix using the given parameters and sends it to the other party.
	 * @param execution Used to get the matrix dimensions.
	 * @return the created matrix.
	 * @throws IOException
	 */
	private KProbeResistantMatrix selectAndSendProbeResistantMatrix(ExecutionParameters execution) throws IOException {
		ArrayList<Integer> inputLabelsP2 = CircuitUtils.getLabels(execution.getBooleanCircuit(), 2);
		return selectAndSendProbeResistantMatrix(inputLabelsP2.size(), execution.statisticalParameter());
	}
	
	/**
	 * Creates a probe resistant matrix with n rows and sends it to the other party.
	 * @param n Number of rows in the required matrix.
	 * @param s statistical parameter.
	 * @return the created matrix.
	 * @throws IOException If there was a problem in the communication.
	 */
	private KProbeResistantMatrix selectAndSendProbeResistantMatrix(int n, int s) throws IOException {
		KProbeResistantMatrixBuilder matrixBuilder = new KProbeResistantMatrixBuilder(n, s);
		KProbeResistantMatrix matrix = matrixBuilder.build();
		channels[0].send(matrix);
		return matrix;
	}
	
	/**
	 * Runs the cut and choose protocol using the given parameters.
	 * @param execution Parameters of the execution of the main circuit, such as number of checked and eval circuits.
	 * @param matrix The matrix that extends the inputs.
	 * @param bundleBuilder Contains the circuit to use.
	 * @return The buckets contain  the evaluated circuits that generated in the protocol executions.
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private BucketList<LimitedBundle> runCutAndChooseProtocol(ExecutionParameters execution, 
			KProbeResistantMatrix matrix, BundleBuilder bundleBuilder) throws IOException, CheatAttemptException {
		//Call the other function with Y2 input indices = null.
		return runCutAndChooseProtocol(execution, matrix, bundleBuilder, null);
	}
	
	/**
	 * Runs the cut and choose protocol using the given parameters.
	 * @param execution Parameters of the execution of the main circuit, such as number of checked and eval circuits.
	 * @param matrix The matrix that extends the inputs.
	 * @param bundleBuilder Contains the circuit to use.
	 * @param inputLabelsY2 The indices of the input labels of Y2.
	 * @return The buckets contain the evaluated circuits that generated in the protocol executions.
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private BucketList<LimitedBundle> runCutAndChooseProtocol(ExecutionParameters execution, KProbeResistantMatrix matrix, 
			BundleBuilder bundleBuilder, int[] inputLabelsY2) throws IOException, CheatAttemptException {
		//Create the cut and choose verifier.
		CutAndChooseVerifier verifier = new CutAndChooseVerifier(execution, primitives, channels, 
				bundleBuilder, matrix, inputLabelsY2);
		//Run the cut and choose protocol.
		verifier.run();
		//Return the buckets that were generated in the cut and choose protocol.
		return verifier.getBuckets();
	}
	
	/**
	 * Runs the Malicious OT protocol.
	 * @param execution Parameters of the circuit.
	 * @param matrix The matrix that used to extend the keys.
	 * @param buckets contains the circuits.
	 */
	private void runObliviousTransferOnP2Keys(ExecutionParameters execution, KProbeResistantMatrix matrix, BucketList<LimitedBundle> buckets) throws CheatAttemptException {
		//Create and run malicious OT routine.
		OfflineOtReceiverRoutine otReceiver = new OfflineOtReceiverRoutine(execution, primitives, maliciousOtReceiver, matrix, channels[0], buckets);
		otReceiver.run();
		
	}
}
