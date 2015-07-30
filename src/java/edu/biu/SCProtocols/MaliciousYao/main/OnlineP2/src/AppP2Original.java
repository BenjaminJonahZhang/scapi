import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import edu.biu.protocols.yao.common.LogTimer;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.Bundle;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.primitives.LimitedBundle;
import edu.biu.protocols.yao.offlineOnline.specs.OnlineProtocolP2;
import edu.biu.protocols.yao.primitives.CheatingRecoveryCircuitCreator;
import edu.biu.protocols.yao.primitives.CircuitInput;
import edu.biu.protocols.yao.primitives.CircuitOutput;
import edu.biu.protocols.yao.primitives.CommunicationConfig;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.KProbeResistantMatrix;
import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit.CircuitType;
import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolOutput;
import edu.biu.scapi.exceptions.CheatAttemptException;

/**
 * This class runs the second party of the online protocol. 
 * It contain multiple 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class AppP2Original {	
	private static final int PARTY = 2;
	private static final String HOME_DIR = "C:/GitHub/Development/MaliciousYaoProtocol/MaliciousYao";
	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyTwoInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/ADD/NigelAdd32.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/ADD/ADDPartyTwoInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/NigelSHA1.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/SHA1PartyTwoInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/SHA256/NigelSHA256.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/SHA256/SHA256PartyTwoInputs.txt";
	private static final String COMM_CONFIG_FILENAME = HOME_DIR + "/assets/conf/Parties1.properties";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/MinCut/NigelMinCircuit.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/MinCut/MinCutPartyTwoInputs.txt";
	
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
	private static int BUCKET_ID = 0;
	
	public static void main(String[] args) {
		CommunicationConfig commConfig = null;
		try {
			 commConfig = new CommunicationConfig(COMM_CONFIG_FILENAME);
		} catch (IOException e) {
			System.exit(1);
		}
		CryptoPrimitives primitives = CryptoPrimitives.defaultPrimitives(8);
		commConfig.connectToOtherParty(1 + primitives.getNumOfThreads());
		
		try {
			// we read the circuit and this party's input from file
			BooleanCircuit mainCircuit = new BooleanCircuit(new File(CIRCUIT_FILENAME));
			CircuitInput input = CircuitInput.fromFile(CIRCUIT_INPUT_FILENAME, mainCircuit, PARTY);
			BooleanCircuit crCircuit = (new CheatingRecoveryCircuitCreator(CIRCUIT_CHEATING_RECOVERY, input.size())).create();

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
			
			FastGarbledBooleanCircuit[] mainGbc = new ScNativeGarbledBooleanCircuit[B1];
			FastGarbledBooleanCircuit[] crGbc = new ScNativeGarbledBooleanCircuit[B2];
			
			
			for (int i=0; i<B1; i++){
				mainGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_FILENAME, CircuitType.FREE_XOR_HALF_GATES, true);
			}
			
			for (int i=0; i<B2; i++){
				crGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_CHEATING_RECOVERY, CircuitType.FREE_XOR_HALF_GATES, true);
			}
			
//			FastGarbledBooleanCircuit[] mainGbc = new ScNativeGarbledBooleanCircuitNoFixedKey[B1];
//			FastGarbledBooleanCircuit[] crGbc = new ScNativeGarbledBooleanCircuitNoFixedKey[B2];
//			
//			
//			for (int i=0; i<B1; i++){
//				//mainGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_FILENAME, true, false, true);
//				mainGbc[i] = new ScNativeGarbledBooleanCircuitNoFixedKey(CIRCUIT_FILENAME, true, false, true,true);
//			}
//			
//			for (int i=0; i<B2; i++){
//				//crGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_CHEATING_RECOVERY, true, false, true);
//				crGbc[i] = new ScNativeGarbledBooleanCircuitNoFixedKey(CIRCUIT_CHEATING_RECOVERY, true, false, true,true);
//			}
			
			ExecutionParameters mainExecution = new ExecutionParameters(mainCircuit, mainGbc, N1, s1, B1, p1);
			ExecutionParameters crExecution = new ExecutionParameters(crCircuit, crGbc, N2, s2, B2, p2);
			
			// we load the bundles from file
			KProbeResistantMatrix mainMatrix = KProbeResistantMatrix.loadFromFile(MAIN_MATRIX);
			KProbeResistantMatrix crMatrix = KProbeResistantMatrix.loadFromFile(CR_MATRIX);
			
			// and run the protocol
			OnlineProtocolP2 protocol = null;
			
			ArrayList<ArrayList<LimitedBundle>> mainBuckets = new ArrayList<ArrayList<LimitedBundle>>();
			ArrayList<ArrayList<LimitedBundle>> crBuckets = new ArrayList<ArrayList<LimitedBundle>>();
			
			int size =N1; 
			
			for ( int i=0; i<N1; i++){

				mainBuckets.add(BucketList.loadLimitedBucketFromFile(String.format("%s.%d.cbundle", BUCKETS_PREFIX_MAIN, BUCKET_ID)));
				crBuckets.add(BucketList.loadLimitedBucketFromFile(String.format("%s.%d.cbundle", BUCKETS_PREFIX_CR, BUCKET_ID++)));
			}
			
			commConfig.getChannels()[0].receive();
				commConfig.getChannels()[0].send("reset times");

			// only now we start counting the running time 
			LogTimer timer = new LogTimer("Online protocol (P2)", true);
			ArrayList<LimitedBundle> tempmainBucket = mainBuckets.get(0);
			ArrayList<LimitedBundle> tempcrBucket = crBuckets.get(0);
			int numberOfTimes = 1;
			long[] average = new long[numberOfTimes];

			int numThreads = 0;
			for (int j=0; j<10; j++){
				primitives = CryptoPrimitives.defaultPrimitives(numThreads);
				System.out.println("start execute "+ numberOfTimes +" times with "+ numThreads +" threads.");
				
				for (int k=0; k<numberOfTimes; k++){
					System.out.println("loop no. "+ k);
					long[] times = new long[size];
									
					for(int i=0; i<size; i++){
						commConfig.getChannels()[0].receive();
						commConfig.getChannels()[0].send("reset times");
						long startinner = System.nanoTime();

						ArrayList<LimitedBundle> mainBucket = mainBuckets.get(i);
						ArrayList<LimitedBundle> crBucket = crBuckets.get(i);
						
						if (i==0){
							System.out.println("starting comparing");
							if (!tempmainBucket.equals(mainBucket)){
								System.out.println("temp is different from the main bucket");
							}
							if (!tempcrBucket.equals(crBucket)){
								System.out.println("temp is different from the cr bucket");
							}
						}
						protocol = new OnlineProtocolP2(mainExecution, crExecution, primitives, commConfig, mainBucket, crBucket, mainMatrix, crMatrix);
						protocol.start(input);
						protocol.run();
						
						long endinner = System.nanoTime();
						times[i] = (endinner - startinner) / 1000000 ;
						//System.out.println("exe no. " +i +" took " + times[i] + " milis.");
					}
				
					int count = 0;
					for (int i=0; i<size; i++){
						count += times[i];
					}
					
					average[k] = (count/size);
					for (int i=0; i<size; i++){
						System.out.print(times[i]+" ");
					}
					System.out.println();
					System.out.println(size+" executions took " + average[k] + " milis.");
				}
						
				int count = 0;
				for (int i=0; i<numberOfTimes; i++){
					count += average[i];
				}
				
				for (int i=0; i<numberOfTimes; i++){
					System.out.print(average[i]+" ");
				}
				System.out.println();
				System.out.println(numberOfTimes+" times of " +size + " executions took " + count/numberOfTimes + " milis.");
				numThreads+=4;
			}
	
			byte[] output = getProtocolOutput(protocol);

			timer.stop();
			printOutput(mainCircuit, output);
			
			Thread.sleep(5000);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static byte[] getProtocolOutput(Protocol protocol) throws CheatAttemptException {
		ProtocolOutput output = protocol.getOutput();
		if (!(output instanceof CircuitOutput)) {
			throw new CheatAttemptException("bad output");
		}
		return ((CircuitOutput)output).getOutput();
	}
	
	private static void printOutput(BooleanCircuit bc, byte[] output) {
		System.out.println("(P2) Received Protocol output:");
		
		System.out.println("output of protocol:");
		for (int i = 0; i < output.length; i++) {
			System.out.print(String.format("%d,",  output[i]));
		}
		System.out.println();
		
		System.out.println("Expected output is:");
		System.out.println("0,1,1,0,1,0,0,1,1,1,0,0,0,1,0,0,1,1,1,0,0,0,0,0,1,1,0,1,1,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,1,0,0,0,0,0,1,0,0,0,0,1,1,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,0,1,1,0,1,1,0,1,1,0,1,1,1,1,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,1,0,1,1,0,1,0");
	}
}
