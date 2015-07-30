import java.io.File;
import java.io.IOException;

import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.primitives.LimitedBundle;
import edu.biu.protocols.yao.offlineOnline.specs.OfflineProtocolP2;
import edu.biu.protocols.yao.primitives.CheatingRecoveryCircuitCreator;
import edu.biu.protocols.yao.primitives.CircuitInput;
import edu.biu.protocols.yao.primitives.CommunicationConfig;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit.CircuitType;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

public class AppP2 {	
	private static final int PARTY = 2;
	private static final String HOME_DIR = "C:/GitHub/Development/MaliciousYaoProtocol/MaliciousYao";
	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyTwoInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/ADD/NigelAdd32.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/ADD/ADDPartyTwoInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/NigelSHA1.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/SHA1PartyTwoInputs.txt";
	private static final String COMM_CONFIG_FILENAME = HOME_DIR + "/assets/conf/Parties1.properties";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/MinCut/NigelMinCircuit.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/MinCut/MinCutPartyTwoInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/MinCut/NigelMinCircuit.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/MinCut/MinCutPartyOneInputs.txt";
	
	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1Input.txt";
	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P2/aes";
	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P2/cr";
	private static final String MAIN_MATRIX = HOME_DIR + "/data/P2/aes.matrix";
	private static final String CR_MATRIX = HOME_DIR + "/data/P2/cr.matrix";
//	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputAdd.txt";
//	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P2/add";
//	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P2/addCr";
//	private static final String MAIN_MATRIX = HOME_DIR + "/data/P2/add.matrix";
//	private static final String CR_MATRIX = HOME_DIR + "/data/P2/AddCr.matrix";
//	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputASha1.txt";
//	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P2/sha";
//	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P2/shaCr";
//	private static final String MAIN_MATRIX = HOME_DIR + "/data/P2/SHA.matrix";
//	private static final String CR_MATRIX = HOME_DIR + "/data/P2/SHACr.matrix";
//	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputMinCut.txt";
//	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P2/minCut";
//	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P2/cr";
//	private static final String MAIN_MATRIX = HOME_DIR + "/data/P2/MinCut.matrix";
//	private static final String CR_MATRIX = HOME_DIR + "/data/P2/cr.matrix";
//	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputMinCut.txt";
//	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/minCut";
//	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/cr";
//	private static final String MAIN_MATRIX = HOME_DIR + "/data/P2/minCut.matrix";
//	private static final String CR_MATRIX = HOME_DIR + "/data/P2/cr.matrix";
	
	public static void main(String[] args) {
		CommunicationConfig commConfig = null;
		try {
			 commConfig = new CommunicationConfig(COMM_CONFIG_FILENAME);
		} catch (IOException e) {
			System.exit(1);
		}
		
		final CryptoPrimitives primitives = CryptoPrimitives.defaultPrimitives(0);
		commConfig.connectToOtherParty(1 + primitives.getNumOfThreads());
		
		try {
			// we read the circuit and this party's input from file
			BooleanCircuit mainCircuit = new BooleanCircuit(new File(CIRCUIT_FILENAME));
			CircuitInput input = CircuitInput.fromFile(CIRCUIT_INPUT_FILENAME, mainCircuit, PARTY);
			BooleanCircuit crCircuit = (new CheatingRecoveryCircuitCreator(CIRCUIT_CHEATING_RECOVERY, input.size())).create();
			
			OTExtensionMaliciousReceiver otReceiver = initMaliciousOtReceiver(mainCircuit.getNumberOfInputs(2), commConfig);
//			int N1 = 10;
//			int B1 = 10;
//			int s1 = 40;
//			double p1 = 0.64;
//			
//			int N2 = 10; //32;
//			int B2 = 10; //31;
//			int s2 = 40;
//			double p2 = 0.64; //0.6;
			
			
//			int N1 = 8;
//			int B1 = 10;
//			int s1 = 40;
//			double p1 = 0.59;
//			
//			int N2 = 8;
//			int B2 = 74;
//			int s2 = 40;
//			double p2 = 0.85;
			
			
			int N1 = 32;
			int B1 = 7;
			int s1 = 40;
			double p1 = 0.62;
			
			int N2 = 32;
			int B2 = 20;
			int s2 = 40;
			double p2 = 0.71;
			
//			int N1 = 128;
//			int B1 = 12;
//			int s1 = 80;
//			double p1 = 0.77;
//			
//			int N2 = 128;
//			int B2 = 28;
//			int s2 = 80;
//			double p2 = 0.75;
			
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
				mainGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_FILENAME, CircuitType.FREE_XOR_HALF_GATES, true);
			}
			
			for (int i=0; i<crGbc.length; i++){
				crGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_CHEATING_RECOVERY, CircuitType.FREE_XOR_HALF_GATES, true);
			}
		
			ExecutionParameters mainExecution = new ExecutionParameters(mainCircuit, mainGbc, N1, s1, B1, p1);
			ExecutionParameters crExecution = new ExecutionParameters(crCircuit, crGbc, N2, s2, B2, p2);
			
			// we start counting the running time just before estalishing communication 
			long start = System.nanoTime();
			
			// and run the protocol
			OfflineProtocolP2 protocol = new OfflineProtocolP2(mainExecution, crExecution, primitives, commConfig, otReceiver, false);
			
			
			System.out.println(String.format("Starting Offline protocol (P1)"));
			protocol.run();
			
			// we measure how much time did the protocol take
			long end = System.nanoTime();
			long runtime = (end - start) / 1000000;
			System.out.println("Offline protocol party 1 took " + runtime + " miliseconds.");
			
			System.out.println(String.format("Saving buckets to files..."));
			start = System.nanoTime();
			
			BucketList<LimitedBundle> mainBuckets = protocol.getMainBuckets();
			BucketList<LimitedBundle> crBuckets = protocol.getCheatingRecoveryBuckets();
			mainBuckets.saveToFiles(BUCKETS_PREFIX_MAIN);
			crBuckets.saveToFiles(BUCKETS_PREFIX_CR);
			KProbeResistantMatrix.saveToFile(protocol.getMainProbeResistantMatrix(), MAIN_MATRIX);
			KProbeResistantMatrix.saveToFile(protocol.getCheatingRecoveryProbeResistantMatrix(), CR_MATRIX);
			
			end = System.nanoTime();
			runtime = (end - start) / 1000000;
			System.out.println("Saving buckets took " + runtime + " miliseconds.");
			
			
			Thread.sleep(5000);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Initializes the malicious OT receiver.
	 * @param numOts The number of OTs to run.
	 */
	private static OTExtensionMaliciousReceiver initMaliciousOtReceiver(int numOts, CommunicationConfig communication) {
		//Get the ip and port of the receiver.
		Party maliciousOtServer = communication.maliciousOtServer();
		String serverAddress = maliciousOtServer.getIpAddress().getHostAddress();
		int serverPort = maliciousOtServer.getPort();
		//Create the malicious OT receiver using the ip, port and number of OTs.
		return new OTExtensionMaliciousReceiver(serverAddress, serverPort, numOts);
	}
}
