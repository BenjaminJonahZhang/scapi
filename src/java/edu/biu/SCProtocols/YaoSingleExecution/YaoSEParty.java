package edu.biu.SCProtocols.YaoSingleExecution;

import edu.biu.SCProtocols.NativeSemiHonestYao.YaoProtocolOutput;
import edu.biu.SCProtocols.gmw.GmwParty;
import edu.biu.SCProtocols.gmw.GmwProtocolInput;
import edu.biu.SCProtocols.gmw.GmwProtocolOutput;
import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolInput;
import edu.biu.scapi.comm.ProtocolOutput;

public class YaoSEParty implements Protocol {

	private long nativeParty;			//A pointer to the native implementation
	private YaoProtocolOutput output;	//The output of the protocol
	
	//JNI functions that call the native implementation
	private native long createYaoSEParty(int id, String circuitFileName, String ip, int port, 
			String inputsFileName);
	private native byte[] runProtocol(long nativeParty);
	private native void runOfflineProtocol(long nativeParty);
	private native byte[] runOnlineProtocol(long nativeParty);
	private native void deleteYaoSE(long nativeParty);
	
	@Override
	public void start(ProtocolInput protocolInput) {
		if (!(protocolInput instanceof YaoSEProtocolInput)){
			throw new IllegalArgumentException("The givan input should be an instance of YaoSEProtocolInput");
		}
		
		YaoSEProtocolInput input = (YaoSEProtocolInput) protocolInput;
		//Creates the native party
		nativeParty = createYaoSEParty(input.getID(), input.getCircuitFileName(), input.getIP(), 
									   input.getPort(), input.getInputsFileName());
	}

	@Override
	public void run() {
		//Executes the native protocol
		byte[] nativeOutput = runProtocol(nativeParty);
		output = new YaoProtocolOutput(nativeOutput);
	}
	
	public void runOffline(){
		//Executes the offline phase protocol
		runOfflineProtocol(nativeParty);
	}
	
	public void runOnline(){
		//Executes the online phase protocol
		byte[] nativeOutput = runOnlineProtocol(nativeParty);
		output = new YaoProtocolOutput(nativeOutput);
	}

	@Override
	public ProtocolOutput getOutput() {
		return output;
	}
	
	/**
	 * deletes the related GMW object
	 */
	protected void finalize() throws Throwable {

		// delete the dynamic allocation of GMW party pointer.
		deleteYaoSE(nativeParty);

		super.finalize();
	}
	
	//loads the dll
	static {
		System.loadLibrary("LibscapiJavaInterface");
	}

	public static void main(String[] args){
		
		int id = new Integer(args[0]); 
		System.out.println("id = " + id);
		String circuitFile = args[1];
		System.out.println("circuitFile = " + circuitFile);
		String ip = args[2];
		System.out.println("ip = " + ip);
		int port = new Integer(args[3]); 
		System.out.println("port = " + port);
		String inputsFile = args[4];
		System.out.println("inputsFile = " + inputsFile);
		
		YaoSEProtocolInput input = new YaoSEProtocolInput(id, circuitFile, ip, port, inputsFile);
		YaoSEParty party = new YaoSEParty();
		party.start(input);
		long start = System.nanoTime();
		party.run();
		long end = System.nanoTime();
		long time =(end - start) / 1000000;
		System.out.println("yao single execution protocol took " + time + " millis.");
		System.out.println("protocol output:");
		YaoProtocolOutput output = (YaoProtocolOutput) party.getOutput();
		byte[] outputBytes = output.getOutput();
		for (int i=0; i<outputBytes.length; i++){
			System.out.print(outputBytes[i] + " ");
		}
		System.out.println();

	}
}
