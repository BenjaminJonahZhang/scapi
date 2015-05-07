import java.io.File;
import java.io.FileWriter;
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
import edu.biu.scapi.exceptions.CircuitFileFormatException;

public class OnlineAppP1ForBatch {
	private static final int PARTY = 1;
	private static final String HOME_DIR = "C:/MaliciousYao";
	private static final String COMM_CONFIG_FILENAME = HOME_DIR + "/assets/conf/Parties0.properties";
	private static int BUCKET_ID = 0;
	
	public static void main(String[] args) throws IOException{
	
		int counter = 0;
		String circuitFile = HOME_DIR + args[counter++];
		String circuitInputFile = HOME_DIR + args[counter++];
		String crCircuitFile = HOME_DIR + args[counter++];
		String mainBucketsPrefix = HOME_DIR + args[counter++];
		String crBucketsPrefix = HOME_DIR + args[counter++];
			
		int N1 = new Integer(args[counter++]);
		int B1 = new Integer(args[counter++]);
		int s1 = new Integer(args[counter++]); 
		double p1 = new Double(args[counter++]);
		int N2 = new Integer(args[counter++]);
		int B2 = new Integer(args[counter++]);
		int s2 = new Integer(args[counter++]); 
		double p2 = new Double(args[counter++]); 
		String outputFile = HOME_DIR + args[counter++];
		
		
		CommunicationConfig commConfig = null;
		try {
			 commConfig = new CommunicationConfig(COMM_CONFIG_FILENAME);
		} catch (IOException e) {
			System.exit(1);
		}
				
		CryptoPrimitives primitives = CryptoPrimitives.defaultPrimitives(8);
		commConfig.connectToOtherParty(1 + primitives.getNumOfThreads());
		System.out.println("N1 = " + N1+ " B1 = "+ B1 + " s1 = "+ s1 + " p1 = "+ p1 + " N2 = " + N2+ " B2 = "+ B2 + 
				" s2 = " + s2+ " p2 = "+ p2);
		
		// we read the circuit and this party's input from file
		BooleanCircuit mainCircuit = null;
		try {
			mainCircuit = new BooleanCircuit(new File(circuitFile));
		} catch (CircuitFileFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CircuitInput input = CircuitInput.fromFile(circuitInputFile, mainCircuit, PARTY);
		BooleanCircuit crCircuit = (new CheatingRecoveryCircuitCreator(crCircuitFile, input.size())).create();
	
		FastGarbledBooleanCircuit[] mainGbc = new ScNativeGarbledBooleanCircuit[B1];
		FastGarbledBooleanCircuit[] crGbc = new ScNativeGarbledBooleanCircuit[B2];
		
		for (int i=0; i<B1; i++){
			mainGbc[i] = new ScNativeGarbledBooleanCircuit(circuitFile, true, false, true);
		}
		
		for (int i=0; i<B2; i++){
			crGbc[i] = new ScNativeGarbledBooleanCircuit(crCircuitFile, true, false, true);
		}
		ExecutionParameters mainExecution = new ExecutionParameters(mainCircuit, mainGbc, N1, s1, B1, p1);
		ExecutionParameters crExecution = new ExecutionParameters(crCircuit, crGbc, N2, s2, B2, p2);
		
		// we load the bundles from file
		ArrayList<ArrayList<Bundle>> mainBuckets = new ArrayList<ArrayList<Bundle>>();
		ArrayList<ArrayList<Bundle>> crBuckets = new ArrayList<ArrayList<Bundle>>();
		
		int size = N1;
		
		for ( int i=0; i<N1; i++){

			try {
				mainBuckets.add(BucketList.loadBucketFromFile(String.format("%s.%d.cbundle", mainBucketsPrefix, BUCKET_ID)));
				crBuckets.add(BucketList.loadBucketFromFile(String.format("%s.%d.cbundle", crBucketsPrefix, BUCKET_ID++)));
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	
		// only now we start counting the running time
		LogTimer timer = new LogTimer("Online protocol (P1)", true);
		
		int numberOfTimes = 20;
		long[] average = new long[numberOfTimes];
		int numThreads = 0;
		
		FileWriter output = new FileWriter(outputFile, true);
		output.append("parameters: N1 = " + N1+ " B1 = "+ B1 + " s1 = "+ s1 + " p1 = "+ p1 + " N2 = " + N2+ " B2 = "+ B2 + 
				" s2 = " + s2+ " p2 = "+ p2 + "\n");
		output.append("Threads number\n");
		
		for (int j=0; j<3; j++){
			output.append(numThreads + " threads,");
			primitives = CryptoPrimitives.defaultPrimitives(numThreads);
			System.out.println("start execute " + numberOfTimes + " times with "+ numThreads +" threads.");

			for (int k=0; k<numberOfTimes; k++){
				System.out.println("loop no. "+ k);
				long[] times = new long[size];
				for(int i=0; i<size; i++){
				
					commConfig.getChannels()[0].send("reset times");
					try {
						commConfig.getChannels()[0].receive();
					} catch (ClassNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
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
				output.append(average[k]+",");
			}
			output.append("\n");
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
		output.close();	
		// we measure how much time did the protocol take
		timer.stop();
		
		commConfig.close();
		
	}
}
