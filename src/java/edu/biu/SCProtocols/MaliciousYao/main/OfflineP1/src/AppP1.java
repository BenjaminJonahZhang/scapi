import java.io.File;
import java.io.IOException;

import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.Bundle;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.specs.OfflineProtocolP1;
import edu.biu.protocols.yao.primitives.CheatingRecoveryCircuitCreator;
import edu.biu.protocols.yao.primitives.CircuitInput;
import edu.biu.protocols.yao.primitives.CommunicationConfig;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousSender;

public class AppP1 {
	private static final int PARTY = 1;
	private static final String HOME_DIR = "C:/GitHub/Development/MaliciousYaoProtocol/MaliciousYao";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/AES_Final-2.txt";
	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyOneInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/ADD/NigelAdd32.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/NigelSHA1.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/SHA1PartyOneInputs.txt";
	private static final String COMM_CONFIG_FILENAME = HOME_DIR + "/assets/conf/Parties0.properties";
	
	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1Input.txt";
	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/aes";
	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/cr";
//	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputAdd.txt";
//	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/add";
//	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/addCr";
//	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputASha1.txt";
//	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/sha";
//	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/shaCr";
	
	public static void main(String[] args) {
		
		
		CommunicationConfig commConfig = null;
		try {
			 commConfig = new CommunicationConfig(COMM_CONFIG_FILENAME);
		} catch (IOException e) {
			System.exit(1);
		}
		
		final CryptoPrimitives primitives = CryptoPrimitives.defaultPrimitives(8);
		commConfig.connectToOtherParty(1 + primitives.getNumOfThreads());
		
		try {
			// we read the circuit and this party's input from file
			BooleanCircuit mainCircuit = new BooleanCircuit(new File(CIRCUIT_FILENAME));
			CircuitInput input = CircuitInput.fromFile(CIRCUIT_INPUT_FILENAME, mainCircuit, PARTY);
			BooleanCircuit crCircuit = (new CheatingRecoveryCircuitCreator(CIRCUIT_CHEATING_RECOVERY, input.size())).create();
			OTExtensionMaliciousSender otSender = initMaliciousOtSender(mainCircuit.getNumberOfInputs(2), commConfig);

//			int N1 = 10;
//			int B1 = 10;
//			int s1 = 40;
//			double p1 = 0.64;
//			
//			int N2 = 10; //32;
//			int B2 = 10; //31;
//			int s2 = 40;
//			double p2 = 0.64; //0.6;
			
			int N1 = 32;
			int B1 = 8;
			int s1 = 40;
			double p1 = 0.73;
			
			int N2 = 32;
			int B2 = 24;
			int s2 = 40;
			double p2 = 0.8;
			
//			int N1 = 128;
//			int B1 = 6;
//			int s1 = 40;
//			double p1 = 0.77;
//			
//			int N2 = 128;
//			int B2 = 14;
//			int s2 = 40;
//			double p2 = 0.76;
			
//			int N1 = 1024;
//			int B1 = 4;
//			int s1 = 40;
//			double p1 = 0.72;
//			
//			int N2 = 1024;
//			int B2 = 10;
//			int s2 = 40;
//			double p2 = 0.85;
			
			FastGarbledBooleanCircuit[] mainGbc;
			FastGarbledBooleanCircuit[] crGbc;
			
			int numOfThread = primitives.getNumOfThreads();
			if (numOfThread >0){
				mainGbc = new ScNativeGarbledBooleanCircuit[numOfThread];
				crGbc = new ScNativeGarbledBooleanCircuit[numOfThread];
			}else{
				mainGbc = new ScNativeGarbledBooleanCircuit[1];
				crGbc = new ScNativeGarbledBooleanCircuit[1];
			}
				
			for (int i=0; i<mainGbc.length; i++){
				mainGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_FILENAME, true, false, true);
			}
			
			for (int i=0; i<crGbc.length; i++){
				crGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_CHEATING_RECOVERY, true, false, true);
			}
			
				
			ExecutionParameters mainExecution = new ExecutionParameters(mainCircuit, mainGbc, N1, s1, B1, p1);
			ExecutionParameters crExecution = new ExecutionParameters(crCircuit, crGbc, N2, s2, B2, p2);
			// we start counting the running time just before estalishing communication 
			long start = System.nanoTime();
			
			// and run the protocol
			OfflineProtocolP1 protocol = new OfflineProtocolP1(mainExecution, crExecution, primitives, commConfig, otSender);
			
			
			System.out.println(String.format("Starting Offline protocol (P1)"));
			protocol.run();
			
			// we measure how much time did the protocol take
			long end = System.nanoTime();
			long runtime = (end - start) / 1000000;
			System.out.println("Offline protocol party 1 took " + runtime + " miliseconds.");
			
			System.out.println(String.format("Saving buckets to files..."));
			start = System.nanoTime();
			
			BucketList<Bundle> mainBuckets = protocol.getMainBuckets();
			BucketList<Bundle> crBuckets = protocol.getCheatingRecoveryBuckets();
			mainBuckets.saveToFiles(BUCKETS_PREFIX_MAIN);
			crBuckets.saveToFiles(BUCKETS_PREFIX_CR);
			
			end = System.nanoTime();
			runtime = (end - start) / 1000000;
			System.out.println("Saving buckets took " + runtime + " miliseconds.");
			
			
			Thread.sleep(5000);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Initializes the malicious OT sender.
	 * @param numOts The number of OTs to run.
	 */
	private static OTExtensionMaliciousSender initMaliciousOtSender(int numOts, CommunicationConfig communication) {
		//Get the data of the OT server.
		Party maliciousOtServer = communication.maliciousOtServer();
		String serverAddress = maliciousOtServer.getIpAddress().getHostAddress();
		int serverPort = maliciousOtServer.getPort();
		
		//Create the Malicious OT sender instance.
		return new OTExtensionMaliciousSender(serverAddress, serverPort, numOts);
	}
}
