package edu.biu.SCProtocols.gmw;

import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolInput;
import edu.biu.scapi.comm.ProtocolOutput;

public class GmwParty implements Protocol{

	private long nativeParty;
	private GmwProtocolOutput output;
	private native long createGMWParty(int id, String circuitFileName, String partiesFileName, 
			String inputsFileName, int numOfThreads);
	private native byte[] runProtocol(long nativeParty);
	
	@Override
	public void start(ProtocolInput protocolInput) {
		if (!(protocolInput instanceof GmwProtocolInput)){
			throw new IllegalArgumentException("The givan input should be an instance of GmwProtocolInput");
		}
		
		GmwProtocolInput input = (GmwProtocolInput) protocolInput;
		nativeParty = createGMWParty(input.getID(), input.getCircuitFileName(), input.getPartiesFileName(), 
									 input.getInputsFileName(), input.getNumOfThreads());
		
	}

	@Override
	public void run() {
		byte[] nativeOutput = runProtocol(nativeParty);
		output = new GmwProtocolOutput(nativeOutput);
	}

	@Override
	public ProtocolOutput getOutput() {
		return output;
	}
	
	//loads the dll
	 static {
	        System.loadLibrary("LibscapiJavaInterface");
	 }

	public static void main(String[] args){
		
		String HOME_DIR = "C:/Github/scapi/scapi/src/java/edu/biu/SCProtocols/gmw/";
		int id = new Integer(args[0]); 
		System.out.println("id = " + id);
		String circuitFile = HOME_DIR + args[1];
		System.out.println("circuitFile = " + circuitFile);
		String partiesFile = HOME_DIR + args[2];
		System.out.println("partiesFile = " + partiesFile);
		String inputsFile = HOME_DIR + args[3];
		System.out.println("inputsFile = " + inputsFile);
		
		int numThreads = new Integer(args[4]);
		System.out.println("numThreads = " + numThreads);
		
		GmwProtocolInput input = new GmwProtocolInput(id, circuitFile, partiesFile, inputsFile, numThreads);
		GmwParty party = new GmwParty();
		party.start(input);
		long start = System.nanoTime();
		party.run();
		long end = System.nanoTime();
		long time =(end - start) / 1000000;
		System.out.println("gmw protocol took " + time + " millis.");
		System.out.println("protocol output:");
		GmwProtocolOutput output = (GmwProtocolOutput) party.getOutput();
		byte[] outputBytes = output.getOutput();
		for (int i=0; i<outputBytes.length; i++){
			System.out.print(outputBytes[i] + " ");
		}
		System.out.println();

	}
}
