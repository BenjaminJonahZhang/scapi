import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

import edu.biu.protocols.yao.common.LogTimer;
import edu.biu.protocols.yao.offlineOnline.primitives.BucketList;
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
import edu.biu.scapi.exceptions.CircuitFileFormatException;

/**
 * This class runs the second party of the online protocol. 
 * It contain multiple 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class OnlineAppP2ForBatch {	
	private static final int PARTY = 2;
	private static final String HOME_DIR = "C:/MaliciousYao";
	private static final String COMM_CONFIG_FILENAME = HOME_DIR + "/assets/conf/Parties1.properties";
	private static int BUCKET_ID = 0;
	
	public static void main(String[] args) throws IOException{
	
		int counter = 0;
		String circuitFile = HOME_DIR + args[counter++];
		String circuitInputFile = HOME_DIR + args[counter++];
		String crCircuitFile = HOME_DIR + args[counter++];
		String mainBucketsPrefix = HOME_DIR + args[counter++];
		String crBucketsPrefix = HOME_DIR + args[counter++];
		String mainMatrixFile = HOME_DIR + args[counter++];
		String crMatrixFile = HOME_DIR + args[counter++];
		
		int N1 = new Integer(args[counter++]);
		int B1 = new Integer(args[counter++]);
		int s1 = new Integer(args[counter++]); 
		double p1 = new Double(args[counter++]);
		int N2 = new Integer(args[counter++]);
		int B2 = new Integer(args[counter++]);
		int s2 = new Integer(args[counter++]); 
		double p2 = new Double(args[counter++]); 
		String outputFile = HOME_DIR + args[counter++];
		boolean readEachTime = new Boolean(args[counter++]);
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
		CircuitInput input = null;
		try {
			mainCircuit = new BooleanCircuit(new File(circuitFile));
			input = CircuitInput.fromFile(circuitInputFile, mainCircuit, PARTY);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CircuitFileFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		BooleanCircuit crCircuit = (new CheatingRecoveryCircuitCreator(crCircuitFile, input.size())).create();
		
		FastGarbledBooleanCircuit[] mainGbc = new ScNativeGarbledBooleanCircuit[B1];
		FastGarbledBooleanCircuit[] crGbc = new ScNativeGarbledBooleanCircuit[B2];
		
		for (int i=0; i<B1; i++){
			mainGbc[i] = new ScNativeGarbledBooleanCircuit(circuitFile, CircuitType.FREE_XOR_HALF_GATES, true);
		}
		
		for (int i=0; i<B2; i++){
			crGbc[i] = new ScNativeGarbledBooleanCircuit(crCircuitFile, CircuitType.FREE_XOR_HALF_GATES, true);
		}
		
		ExecutionParameters mainExecution = new ExecutionParameters(mainCircuit, mainGbc, N1, s1, B1, p1);
		ExecutionParameters crExecution = new ExecutionParameters(crCircuit, crGbc, N2, s2, B2, p2);
		
		// we load the bundles from file
		KProbeResistantMatrix mainMatrix = null;
		KProbeResistantMatrix crMatrix = null;
		try {
			mainMatrix = KProbeResistantMatrix.loadFromFile(mainMatrixFile);
			crMatrix = KProbeResistantMatrix.loadFromFile(crMatrixFile);
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// and run the protocol
		OnlineProtocolP2 protocol = null;
		
		ArrayList<ArrayList<LimitedBundle>> mainBuckets = new ArrayList<ArrayList<LimitedBundle>>();
		ArrayList<ArrayList<LimitedBundle>> crBuckets = new ArrayList<ArrayList<LimitedBundle>>();
		
		if (!readEachTime){
			for ( int i=0; i<N1; i++){

				try {
					mainBuckets.add(BucketList.loadLimitedBucketFromFile(String.format("%s.%d.cbundle", mainBucketsPrefix, BUCKET_ID)));
					crBuckets.add(BucketList.loadLimitedBucketFromFile(String.format("%s.%d.cbundle", crBucketsPrefix, BUCKET_ID++)));
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		int size = N1; 
		
		// only now we start counting the running time 
		LogTimer timer = new LogTimer("Online protocol (P2)", true);
		
		int numberOfTimes = 20;
		long[] average = new long[numberOfTimes];
		
		FileWriter outputF = new FileWriter(outputFile, true);
		outputF.append("parameters: N1 = " + N1+ " B1 = "+ B1 + " s1 = "+ s1 + " p1 = "+ p1 + " N2 = " + N2+ " B2 = "+ B2 + 
				" s2 = " + s2+ " p2 = "+ p2 + "\n");
		outputF.append("Threads number\n");
		
		int numThreads = 0;
		for (int j=0; j<3; j++){
			outputF.append(numThreads + " threads,");
			primitives = CryptoPrimitives.defaultPrimitives(numThreads);
			System.out.println("start execute "+ numberOfTimes +" times with "+ numThreads +" threads.");
			
			for (int k=0; k<numberOfTimes; k++){
				System.out.println("loop no. "+ k);
				long[] times = new long[size];
								
				for(int i=0; i<size; i++){

					ArrayList<LimitedBundle> mainBucket = null;
					ArrayList<LimitedBundle> crBucket = null;
					if (readEachTime){
						try {
							mainBucket = BucketList.loadLimitedBucketFromFile(String.format("%s.%d.cbundle", mainBucketsPrefix, i));
							crBucket = BucketList.loadLimitedBucketFromFile(String.format("%s.%d.cbundle", crBucketsPrefix, i));
						} catch (ClassNotFoundException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else{
						mainBucket = mainBuckets.get(i);
						crBucket = crBuckets.get(i);
					}
					
					try {
						commConfig.getChannels()[0].receive();
					} catch (ClassNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					commConfig.getChannels()[0].send("reset times");
					long startinner = System.nanoTime();
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
				outputF.append(average[k]+",");
				
			}
			outputF.append("\n");
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
		outputF.close();		

		byte[] output = getProtocolOutput(protocol);

		timer.stop();
		printOutput(output);
		
		commConfig.close();
	}
	
	private static byte[] getProtocolOutput(Protocol protocol) throws CheatAttemptException {
		ProtocolOutput output = protocol.getOutput();
		if (!(output instanceof CircuitOutput)) {
			throw new CheatAttemptException("bad output");
		}
		return ((CircuitOutput)output).getOutput();
	}
	
	private static void printOutput(byte[] output) {
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
