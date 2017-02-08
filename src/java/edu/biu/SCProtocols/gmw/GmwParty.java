package edu.biu.SCProtocols.gmw;

import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolInput;
import edu.biu.scapi.comm.ProtocolOutput;

/**
 * This is a wrapper to the native implementation of the GMW protocol. <p>
 * A general explanation of the GMW protocol can be found at {@link http://crypto.biu.ac.il/sites/default/files/Winter%20School%2015%20-%20GMW%20and%20OT%20extension.pdf}.
 * This implementation is more efficient since we use Beaver's multiplication triples instead of 1 out of 4 OT. <P>
 * 
 * The native implementation can be found at {@link https://github.com/cryptobiu/libscapi/tree/dev/protocols/GMW}<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GmwParty implements Protocol{

	private long nativeParty;			//A pointer to the native implementation
	private GmwProtocolOutput output;	//The output of the protocol
	
	//JNI functions that call the native implementation
	private native long createGMWParty(int id, String circuitFileName, String partiesFileName, 
			String inputsFileName, int numOfThreads);
	private native byte[] runProtocol(long nativeParty);
	private native void deleteGMW(long nativeParty);
	
	@Override
	public void start(ProtocolInput protocolInput) {
		if (!(protocolInput instanceof GmwProtocolInput)){
			throw new IllegalArgumentException("The givan input should be an instance of GmwProtocolInput");
		}
		
		GmwProtocolInput input = (GmwProtocolInput) protocolInput;
		//Creates the native party
		nativeParty = createGMWParty(input.getID(), input.getCircuitFileName(), input.getPartiesFileName(), 
									 input.getInputsFileName(), input.getNumOfThreads());
	}

	@Override
	public void run() {
		//Executes the native protocol
		byte[] nativeOutput = runProtocol(nativeParty);
		output = new GmwProtocolOutput(nativeOutput);
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
		deleteGMW(nativeParty);

		super.finalize();
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
