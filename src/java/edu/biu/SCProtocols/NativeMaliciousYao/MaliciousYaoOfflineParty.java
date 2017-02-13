package edu.biu.SCProtocols.NativeMaliciousYao;

import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolInput;
import edu.biu.scapi.comm.ProtocolOutput;

/**
 * This is a wrapper to the native implementation of the offline phase of the malicious yao protocol. <p>
 * The full protocol specification is described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for
 * Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, page 18 - section E, "The Full Protocol Specification". <p>
 * 
 * Since c++ implementation is usually more efficient than the java implementation, we chose to wrap our c++ implementation 
 * of this protocol, along with the java implementation. This way, we can compare the results, times, and other performance issues.
 *   
 * The native implementation can be found at <a href="https://github.com/cryptobiu/libscapi/tree/dev/protocols/MaliciousYao">https://github.com/cryptobiu/libscapi/tree/dev/protocols/MaliciousYao</a>.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class MaliciousYaoOfflineParty implements Protocol {

	private long nativeParty;	//A pointer to the native implementation
	private int id;
	
	//JNI functions that call the native implementation
	private native long createYaoParty(int id, String configFileName);
	private native void runProtocol(int id, long nativeParty);
	private native void deleteMaliciousYao(int id, long nativeParty);
	
	@Override
	public void start(ProtocolInput protocolInput) {
		if (!(protocolInput instanceof MaliciousYaoProtocolInput)){
			throw new IllegalArgumentException("The givan input should be an instance of MaliciousYaoProtocolInput");
		}
		
		MaliciousYaoProtocolInput input = (MaliciousYaoProtocolInput) protocolInput;
		nativeParty = createYaoParty(input.getID(), input.getConfigFileName());
		id = input.getID();
	}

	@Override
	public void run() {
		runProtocol(id, nativeParty);
	}

	@Override
	public ProtocolOutput getOutput() {
		return null;
	}

	//loads the dll
	static {
		System.loadLibrary("LibscapiJavaInterface");
	}
	
	/**
	 * deletes the related Yao object
	 */
	protected void finalize() throws Throwable {

		// delete the dynamic allocation of Yao party.
		deleteMaliciousYao(id, nativeParty);

		super.finalize();
	}
		 
	public static void main(String[] args) {
		//String HOME_DIR = "C:/Github/scapi/scapi/src/java/edu/biu/SCProtocols/NativeMaliciousYao/";
		int id = new Integer(args[0]); 
		System.out.println("id = " + id);
		String configFile = args[1];
		System.out.println("configFile = " + configFile);
		
		MaliciousYaoProtocolInput input = new MaliciousYaoProtocolInput(id, configFile);
		MaliciousYaoOfflineParty party = new MaliciousYaoOfflineParty();
		party.start(input);
		long start = System.nanoTime();
		party.run();
		long end = System.nanoTime();
		long time =(end - start) / 1000000;
		System.out.println("malicious yao offline protocol took " + time + " millis.");
	}

}
