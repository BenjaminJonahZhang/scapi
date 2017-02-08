package edu.biu.SCProtocols.NativeSemiHonestYao;

import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolInput;
import edu.biu.scapi.comm.ProtocolOutput;

/**
 * This is a wrapper to the native implementation of the semi honest Yao protocol. <p>
 * The native implementation can be found at {@link https://github.com/cryptobiu/libscapi/tree/dev/protocols/SemiHonestYao}<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class YaoParty implements Protocol{

	private long nativeParty;			//A pointer to the native implementation
	private YaoProtocolOutput output;	//The output of the protocol
	private int id;
	
	//JNI functions that call the native implementation
	private native long createYaoParty(int id, String configFileName);
	private native byte[] runProtocol(int id, long nativeParty);
	private native void deleteYao(int id, long nativeParty);
	
	@Override
	public void start(ProtocolInput protocolInput) {
		if (!(protocolInput instanceof YaoProtocolInput)){
			throw new IllegalArgumentException("The givan input should be an instance of YaoProtocolInput");
		}
		
		YaoProtocolInput input = (YaoProtocolInput) protocolInput;
		nativeParty = createYaoParty(input.getID(), input.getConfigFileName());
		id = input.getID();
	}

	@Override
	public void run() {
		byte[] nativeOutput = runProtocol(id, nativeParty);
		output = new YaoProtocolOutput(nativeOutput);
	}

	@Override
	public ProtocolOutput getOutput() {
		return output;
	}
	
	/**
	 * deletes the related Yao object
	 */
	protected void finalize() throws Throwable {

		// delete the dynamic allocation of Yao party.
		deleteYao(id, nativeParty);

		super.finalize();
	}
	
	//loads the dll
	 static {
		 System.loadLibrary("LibscapiJavaInterface");
	 }

	public static void main(String[] args) {
		String HOME_DIR = "C:/Github/scapi/scapi/src/java/edu/biu/SCProtocols/NativeSemiHonestYao/";
		int id = new Integer(args[0]); 
		String configFile = HOME_DIR + args[1];
		
		YaoProtocolInput input = new YaoProtocolInput(id, configFile);
		YaoParty party = new YaoParty();
		party.start(input);
		long start = System.nanoTime();
		party.run();
		long end = System.nanoTime();
		long time =(end - start) / 1000000;
		System.out.println("yao protocol took " + time + " millis.");
		YaoProtocolOutput output = (YaoProtocolOutput) party.getOutput();
		byte[] outputBytes = output.getOutput();
		System.out.println("output lentgh = " + outputBytes.length);
		System.out.println("protocol output:");
		for (int i=0; i<outputBytes.length; i++){
			System.out.print(outputBytes[i] + " ");
		}
		System.out.println();

	}

}
