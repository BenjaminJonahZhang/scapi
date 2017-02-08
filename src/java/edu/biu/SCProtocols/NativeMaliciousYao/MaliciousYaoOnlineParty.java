package edu.biu.SCProtocols.NativeMaliciousYao;

import edu.biu.scapi.comm.Protocol;
import edu.biu.scapi.comm.ProtocolInput;
import edu.biu.scapi.comm.ProtocolOutput;
import edu.biu.SCProtocols.NativeSemiHonestYao.YaoProtocolOutput;

public class MaliciousYaoOnlineParty implements Protocol {

	private long nativeParty;
	private YaoProtocolOutput output;
	private int id;
	private native long createYaoParty(int id, String configFileName, String ecFileName);
	private native byte[] runProtocol(int id, long nativeParty, int startExecutionIndex, int endExecutionIndex);
	
	@Override
	public void start(ProtocolInput protocolInput) {
		if (!(protocolInput instanceof MaliciousYaoProtocolInput)){
			throw new IllegalArgumentException("The givan input should be an instance of MaliciousYaoProtocolInput");
		}
		
		MaliciousYaoProtocolInput input = (MaliciousYaoProtocolInput) protocolInput;
		nativeParty = createYaoParty(input.getID(), input.getConfigFileName(), input.getECFileName());
		id = input.getID();
	}

	@Override
	public void run() {
		output = new YaoProtocolOutput(runProtocol(id, nativeParty, 0, 32));
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
		String HOME_DIR = "C:/Github/scapi/scapi/src/java/edu/biu/SCProtocols/NativeMaliciousYao/";
		int id = new Integer(args[0]); 
		System.out.println("id = " + id);
		String configFile = HOME_DIR + args[1];
		String ecFile = "C:/Github/libscapi/include/configFiles/NISTEC.txt";
		System.out.println("configFile = " + configFile);
		
		MaliciousYaoProtocolInput input = new MaliciousYaoProtocolInput(id, configFile, ecFile);
		MaliciousYaoOnlineParty party = new MaliciousYaoOnlineParty();
		party.start(input);
		party.run();
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
