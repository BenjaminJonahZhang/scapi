package edu.biu.protocols.yao.offlineOnline.specs;

import java.io.IOException;

import javax.crypto.SecretKey;

import edu.biu.protocols.yao.common.LogTimer;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.Bundle;
import edu.biu.protocols.yao.offlineOnline.primitives.BundleBuilder;
import edu.biu.protocols.yao.offlineOnline.primitives.CheatingRecoveryBundleBuilder;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.subroutines.CutAndChooseProver;
import edu.biu.protocols.yao.offlineOnline.subroutines.OfflineOtSenderRoutine;
import edu.biu.protocols.yao.primitives.CommunicationConfig;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.Expector;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousSender;

/**
 * This class represents the first party in the offline phase of Malicious Yao protocol. <P>
 * 
 * The full protocol specification is described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for 
 * Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, page 18 - section E, "The Full Protocol Specification".
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class OfflineProtocolP1 {
	private final ExecutionParameters mainExecution;	// Parameters of the main circuit.
	private final ExecutionParameters crExecution;		// Parameters of the cheating recovery circuit.
	private final CryptoPrimitives primitives;			// Contains the low level instances to use.
	private final Channel[] channels;						// The channel used communicate between the parties.
	
	private KProbeResistantMatrix mainMatrix;			//The probe-resistant matrix that used to extend the main circuit's keys.
	private KProbeResistantMatrix crMatrix;				//The probe-resistant matrix that used to extend the ceating recovery circuit's keys.
	private BucketList<Bundle> mainBuckets;				//Contain the main circuits.
	private BucketList<Bundle> crBuckets;				//Contain the cheating recovery circuits.
	private OTExtensionMaliciousSender maliciousOtSender;	//The malicious OT used to transfer the keys.
	
	/**
	 * Constructor that sets the parameters. 
	 * @param mainExecution Parameters of the main circuit.
	 * @param crExecution Parameters of the cheating recovery circuit.
	 * @param primitives Contains the low level instances to use.
	 * @param communication Configuration of communication between parties.
	 */
	public OfflineProtocolP1(ExecutionParameters mainExecution, ExecutionParameters crExecution, CryptoPrimitives primitives, 
			CommunicationConfig communication, OTExtensionMaliciousSender maliciousOtSender) {
		this.mainExecution = mainExecution;
		this.crExecution = crExecution;
		this.primitives = primitives;
		this.channels = communication.getChannels();	// Get the channel from the communication configuration.
		this.maliciousOtSender = maliciousOtSender;
	}
	
	/**
	 * Runs the first party in the offline phase of the malicious Yao protocol.
	 */
	public void run() {
		
		//LogTimer timer = new LogTimer("Offline protocol");
		try {
			// Pick master proof of cheating (true for all buckets!!!).
			SecretKey proofOfCheating = primitives.getMultiKeyEncryptionScheme().generateKey();
			
			//timer.reset("receiving probe resistant matrices");
			// Receive matrices from p2.
			mainMatrix = receiveProbeResistantMatrix();
			crMatrix = receiveProbeResistantMatrix();
			//timer.stop();
			
			
			//timer.reset("init bundle builders...");
			//Create bundle builders of the main circuit and for the cheating recovery circuit.
			//In order to use threads, create bundle for each thread.
			BundleBuilder[] mainBundleBuilder;
			BundleBuilder[] crBundleBuilder;
			int size;
			if (primitives.getNumOfThreads() > 0){
				size = primitives.getNumOfThreads();
			} else{
				size = 1;
			}
			mainBundleBuilder = new BundleBuilder[size];
			crBundleBuilder = new BundleBuilder[size];
				
			for (int i=0; i<size; i++){
				mainBundleBuilder[i] = new BundleBuilder(mainExecution.getCircuit(i), mainMatrix, primitives, channels);
				crBundleBuilder[i] = new CheatingRecoveryBundleBuilder(crExecution.getCircuit(i), crMatrix, primitives, channels, proofOfCheating);
			}
			//timer.stop();

			//timer.reset("runCutAndChooseProtocol(AES)");
			//Run Cut and Choose protocol on the main circuit.
			mainBuckets = runCutAndChooseProtocol(mainExecution, mainBundleBuilder); 
			//timer.stop();
			
		//	timer.reset("runCutAndChooseProtocol(CR)");
			//Run Cut and Choose protocol on the cheating recovery circuit.
			crBuckets = runCutAndChooseProtocol(crExecution, crBundleBuilder); 
		//	timer.stop();
			
		//	timer.reset("runObliviousTransferOnP2Keys(AES)");
			//Run OT on p2 keys of the main circuit.
			runObliviousTransferOnP2Keys(mainExecution, mainMatrix, mainBuckets);
		//	timer.stop();
			
		//	timer.reset("runObliviousTransferOnP2Keys(CR)");
			//Run OT on p2 keys of the cheating recovery circuit.
			runObliviousTransferOnP2Keys(crExecution, crMatrix, crBuckets);
		//	timer.stop();
			
		} catch (CheatAttemptException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * @return the buckets of the main circuit.
	 */
	public BucketList<Bundle> getMainBuckets() {
		return mainBuckets;
	}
	
	/**
	 * @return the buckets of the cheating recovery circuit.
	 */
	public BucketList<Bundle> getCheatingRecoveryBuckets() {
		return crBuckets;
	}
	
	/**
	 * Runs the Cut and Choose protocol on the given circuit (in the ExecutionParameters object).
	 * @param execution Contains parameters for the execution.
	 * @param bundleBuilders Contains values used in the circuit (such as keys, wires indices).
	 * @return list of buckets that holds the created circuits.
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private BucketList<Bundle> runCutAndChooseProtocol(ExecutionParameters execution, BundleBuilder[] bundleBuilders) 
			throws IOException, CheatAttemptException {
		//Create and run Cut and Choose prover instance.
		CutAndChooseProver prover = new CutAndChooseProver(execution, primitives, channels, bundleBuilders);
		prover.run();
		return prover.getBuckets();
	}

	/**
	 * Receive KProbeResistantMatrix from P2.
	 * @return the received matrix.
	 * @throws CheatAttemptException
	 * @throws IOException
	 */
	private KProbeResistantMatrix receiveProbeResistantMatrix() throws CheatAttemptException, IOException {
		Expector expector = new Expector(channels[0], KProbeResistantMatrix.class);
		return (KProbeResistantMatrix) expector.receive();
	}
	
	/**
	 * Runs the Malicious OT protocol.
	 * @param execution Parameters of the circuit.
	 * @param matrix The matrix that used to extend the keys.
	 * @param buckets contains the circuits.
	 */
	private void runObliviousTransferOnP2Keys(ExecutionParameters execution, KProbeResistantMatrix matrix, BucketList<Bundle> buckets) {
		//Create and run malicious OT routine.
		OfflineOtSenderRoutine otSender = new OfflineOtSenderRoutine(execution, primitives, maliciousOtSender, matrix, buckets);
		otSender.run();
	}
	
	
}
