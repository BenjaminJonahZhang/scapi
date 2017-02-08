package edu.biu.SCProtocols.NativeSemiHonestYao;

import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolInput;
import edu.biu.scapi.comm.ProtocolOutput;

public class YaoParty implements Protocol{

	private long nativeParty;
	private YaoProtocolOutput output;
	private int id;
	private int numberOfIterations;
	private native long createYaoParty(int id, String configFileName);
	private native byte[] runProtocol(int numberOfIterations, int id, long nativeParty);
	
	@Override
	public void start(ProtocolInput protocolInput) {
		if (!(protocolInput instanceof YaoProtocolInput)){
			throw new IllegalArgumentException("The givan input should be an instance of YaoProtocolInput");
		}
		
		YaoProtocolInput input = (YaoProtocolInput) protocolInput;
		nativeParty = createYaoParty(input.getID(), input.getConfigFileName());
		id = input.getID();
		numberOfIterations = input.getNumberOfIterations();
		System.out.println("end start");
	}

	@Override
	public void run() {
		byte[] nativeOutput = runProtocol(numberOfIterations, id, nativeParty);
		output = new YaoProtocolOutput(nativeOutput);
	}

	@Override
	public ProtocolOutput getOutput() {
		return output;
	}
	
	//loads the dll
	 static {
		 System.loadLibrary("LibscapiJavaInterface");
	 }

	public static void main(String[] args) {
		String HOME_DIR = "C:/Github/scapi/scapi/src/java/edu/biu/SCProtocols/NativeSemiHonestYao/";
		int id = new Integer(args[0]); 
		System.out.println("id = " + id);
		String configFile = HOME_DIR + args[1];
		System.out.println("configFile = " + configFile);
		int numberOfIterations = new Integer(args[2]); 
		
		YaoProtocolInput input = new YaoProtocolInput(numberOfIterations, id, configFile);
		YaoParty party = new YaoParty();
		party.start(input);
		long start = System.nanoTime();
		party.run();
		long end = System.nanoTime();
		long time =(end - start) / 1000000;
		System.out.println("yao protocol took " + time + " millis.");
		System.out.println("protocol output:");
		YaoProtocolOutput output = (YaoProtocolOutput) party.getOutput();
		System.out.println("after get output");
		byte[] outputBytes = output.getOutput();
		System.out.println("output lentgh = " + outputBytes.length);
		for (int i=0; i<outputBytes.length; i++){
			System.out.print(outputBytes[i] + " ");
		}
		System.out.println();

	}

}
