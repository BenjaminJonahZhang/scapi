import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import edu.biu.protocols.yao.common.LogTimer;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
import edu.biu.protocols.yao.offlineOnline.primitives.Bundle;
import edu.biu.protocols.yao.offlineOnline.primitives.ExecutionParameters;
import edu.biu.protocols.yao.offlineOnline.specs.OnlineProtocolP1;
import edu.biu.protocols.yao.primitives.CheatingRecoveryCircuitCreator;
import edu.biu.protocols.yao.primitives.CircuitInput;
import edu.biu.protocols.yao.primitives.CommunicationConfig;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit.CircuitType;

public class AppP1Original {
	private static final int PARTY = 1;
	private static final String HOME_DIR = "C:/GitHub/Development/MaliciousYaoProtocol/MaliciousYao";
	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyOneInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/ADD/NigelAdd32.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/ADD/ADDPartyOneInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/NigelSHA1.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/SHA1PartyOneInputs.txt";
//	private static final String CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/SHA256/NigelSHA256.txt";
//	private static final String CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/SHA256/SHA256PartyOneInputs.txt";
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
//	private static final String CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputSHA256.txt";
//	private static final String BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/sha256";
//	private static final String BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/cr";
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
//		
			FastGarbledBooleanCircuit[] mainGbc = new ScNativeGarbledBooleanCircuit[B1];
			FastGarbledBooleanCircuit[] crGbc = new ScNativeGarbledBooleanCircuit[B2];
			
//			FastGarbledBooleanCircuit[] mainGbc = new ScNativeGarbledBooleanCircuitNoFixedKey[B1];
//			FastGarbledBooleanCircuit[] crGbc = new ScNativeGarbledBooleanCircuitNoFixedKey[B2];
			
			
			for (int i=0; i<B1; i++){
				mainGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_FILENAME, CircuitType.FREE_XOR_HALF_GATES, true);
			}
			
			for (int i=0; i<B2; i++){
				crGbc[i] = new ScNativeGarbledBooleanCircuit(CIRCUIT_CHEATING_RECOVERY, CircuitType.FREE_XOR_HALF_GATES, true);
			}
			
			ExecutionParameters mainExecution = new ExecutionParameters(mainCircuit, mainGbc, N1, s1, B1, p1);
			ExecutionParameters crExecution = new ExecutionParameters(crCircuit, crGbc, N2, s2, B2, p2);
			
			// we load the bundles from file
			

			// and run the protocol
			ArrayList<ArrayList<Bundle>> mainBuckets = new ArrayList<ArrayList<Bundle>>();
			ArrayList<ArrayList<Bundle>> crBuckets = new ArrayList<ArrayList<Bundle>>();
			
			int size = N1;
			
			for ( int i=0; i<N1; i++){

				mainBuckets.add(BucketList.loadBucketFromFile(String.format("%s.%d.cbundle", BUCKETS_PREFIX_MAIN, BUCKET_ID)));
				crBuckets.add(BucketList.loadBucketFromFile(String.format("%s.%d.cbundle", BUCKETS_PREFIX_CR, BUCKET_ID++)));
			}
			
		//	for(int i=0; i<100; i++){
				commConfig.getChannels()[0].send("reset times");
				commConfig.getChannels()[0].receive();
		//	}
			// only now we start counting the running time
			LogTimer timer = new LogTimer("Online protocol (P1)", true);
			
			int numberOfTimes = 1;
			long[] average = new long[numberOfTimes];
//			System.out.println("enter something...");
//			System.in.read();
			int numThreads = 0;
			for (int j=0; j<10; j++){
				primitives = CryptoPrimitives.defaultPrimitives(numThreads);
				System.out.println("start execute 1000 times with "+ numThreads +" threads.");
	
				for (int k=0; k<numberOfTimes; k++){
					System.out.println("loop no. "+ k);
					long[] times = new long[size];
					for(int i=0; i<size; i++){
					
						commConfig.getChannels()[0].send("reset times");
						commConfig.getChannels()[0].receive();
						long startinner = System.nanoTime();
						ArrayList<Bundle> mainBucket = mainBuckets.get(i);
						ArrayList<Bundle> crBucket = crBuckets.get(i);
						
						OnlineProtocolP1 protocol = new OnlineProtocolP1(mainExecution, crExecution, primitives, commConfig, mainBucket, crBucket);
						protocol.start(input);
						protocol.run();
						long endinner = System.nanoTime();
						times[i] =(endinner - startinner) / 1000000;
						//System.out.println("exe no. " +i+" took " + times[i] + " milis.");
					}

					int count = 0;
					for (int i=0; i<size; i++){
						count += times[i];
					}
					
					average[k] = count/size;
					
					for (int i=0; i<size; i++){
						System.out.print(times[i]+" ");
					}
					
					System.out.println();
					System.out.println(size+" executions took " +  average[k] + " milis.");
				}
					
			int count = 0;
			for (int i=0; i<numberOfTimes; i++){
				count += average[i];
			}
			
			for (int i=0; i<numberOfTimes; i++){
				System.out.print(average[i]+" ");
			}
			System.out.println();
			System.out.println(numberOfTimes+" times of +" +size + " executions took " + count/numberOfTimes + " milis.");
			
			numThreads+=4;
		}
			// we measure how much time did the protocol take
			timer.stop();
			
			Thread.sleep(5000);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
