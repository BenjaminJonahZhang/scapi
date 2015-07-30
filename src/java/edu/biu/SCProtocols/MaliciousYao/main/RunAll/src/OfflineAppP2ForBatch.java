import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
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
import edu.biu.scapi.exceptions.CircuitFileFormatException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

public class OfflineAppP2ForBatch {	
	private static final int PARTY = 2;
	private static final String HOME_DIR = "C:/MaliciousYao";
	private static final String COMM_CONFIG_FILENAME = HOME_DIR + "/assets/conf/Parties1.properties";

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
		int numOfThread = new Integer(args[counter++]); 
		String outputFile = HOME_DIR + args[counter++];
		Boolean addFileTitle = new Boolean(args[counter++]); 
		Boolean addThreadsTitle = new Boolean(args[counter++]);
		Boolean newLine = new Boolean(args[counter++]);
		Boolean saveToDisk = new Boolean(args[counter++]);
		Boolean writeTablesToDisk = new Boolean(args[counter++]);
		System.out.println("N1 = " + N1+ " B1 = "+ B1 + " s1 = "+ s1 + " p1 = "+ p1 + " N2 = " + N2+ " B2 = "+ B2 + 
				" s2 = " + s2+ " p2 = "+ p2 + "numOfThread = " + numOfThread);
		System.out.println("addFileTitle =  "+ addFileTitle + " addThreadsTitle = "+ addThreadsTitle+ " newLine = "+ newLine+ " SaveToDisk = "+ saveToDisk);
		
		CommunicationConfig commConfig = null;
		try {
			 commConfig = new CommunicationConfig(COMM_CONFIG_FILENAME);
		} catch (IOException e) {
			System.exit(1);
		}
		
		CryptoPrimitives primitives = CryptoPrimitives.defaultPrimitives(numOfThread);
		commConfig.connectToOtherParty(1 + primitives.getNumOfThreads());
		BooleanCircuit mainCircuit = null;
		CircuitInput input = null;
		// we read the circuit and this party's input from file
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
		
		OTExtensionMaliciousReceiver otReceiver = null;
		try {
			otReceiver = initMaliciousOtReceiver(mainCircuit.getNumberOfInputs(2), commConfig);
		} catch (NoSuchPartyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		FastGarbledBooleanCircuit[] mainGbc;
		FastGarbledBooleanCircuit[] crGbc;
		
		if (numOfThread >0){
			mainGbc = new ScNativeGarbledBooleanCircuit[numOfThread];
			crGbc = new ScNativeGarbledBooleanCircuit[numOfThread];
		}else{
			mainGbc = new ScNativeGarbledBooleanCircuit[1];
			crGbc = new ScNativeGarbledBooleanCircuit[1];
			
		}
		for (int i=0; i<mainGbc.length; i++){
			mainGbc[i] = new ScNativeGarbledBooleanCircuit(circuitFile, CircuitType.FREE_XOR_HALF_GATES, true);
		}
		
		for (int i=0; i<crGbc.length; i++){
			crGbc[i] = new ScNativeGarbledBooleanCircuit(crCircuitFile, CircuitType.FREE_XOR_HALF_GATES, true);
		}
		
		ExecutionParameters mainExecution = new ExecutionParameters(mainCircuit, mainGbc, N1, s1, B1, p1);
		ExecutionParameters crExecution = new ExecutionParameters(crCircuit, crGbc, N2, s2, B2, p2);
		
		OfflineProtocolP2 protocol = null;
		
		FileWriter output = new FileWriter(outputFile, true);
		
		if (addFileTitle){
			output.append("parameters: N1 = " + N1+ " B1 = "+ B1 + " s1 = "+ s1 + " p1 = "+ p1 + " N2 = " + N2+ " B2 = "+ B2 + 
					" s2 = " + s2+ " p2 = "+ p2 + "\n");
			output.append("Threads number\n");
		}
		
		if (addThreadsTitle){
			output.append(numOfThread + " threads,");
		}
		
		// we start counting the running time just before estalishing communication 
		long start = System.nanoTime();
		
		// and run the protocol
		protocol = new OfflineProtocolP2(mainExecution, crExecution, primitives, commConfig, otReceiver, writeTablesToDisk);
		
		
		System.out.println(String.format("Starting Offline protocol (P2)"));
		protocol.run();
		
		// we measure how much time did the protocol take
		long end = System.nanoTime();
		long runtime = (end - start) / 1000000;
		System.out.println("Offline protocol party 1 took " + runtime + " miliseconds.");
		output.append(runtime+",");
			
		if (newLine){
			output.append("\n");
		}
		output.close();
		
		if (saveToDisk){
			System.out.println(String.format("Saving buckets to files..."));
			start = System.nanoTime();
			
			BucketList<LimitedBundle> mainBuckets = protocol.getMainBuckets();
			BucketList<LimitedBundle> crBuckets = protocol.getCheatingRecoveryBuckets();
			try {
				mainBuckets.saveToFiles(mainBucketsPrefix);
				crBuckets.saveToFiles(crBucketsPrefix);
				KProbeResistantMatrix.saveToFile(protocol.getMainProbeResistantMatrix(), mainMatrixFile);
				KProbeResistantMatrix.saveToFile(protocol.getCheatingRecoveryProbeResistantMatrix(), crMatrixFile);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			end = System.nanoTime();
			runtime = (end - start) / 1000000;
			System.out.println("Saving buckets took " + runtime + " miliseconds.");
		}
		commConfig.close();
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
