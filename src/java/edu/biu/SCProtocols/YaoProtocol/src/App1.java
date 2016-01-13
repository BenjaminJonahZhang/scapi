import java.io.File;
import java.io.FileNotFoundException;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuit.CircuitType;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.CommunicationSetup;
import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
import edu.biu.scapi.comm.LoadParties;
import edu.biu.scapi.comm.NaiveSuccess;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
import edu.biu.scapi.comm.twoPartyComm.NativeSocketCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.TwoPartyCommunicationSetup;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTSemiHonestExtensionSender;

/**
 * This application runs party one of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
@SuppressWarnings("deprecation")
public class App1 {
	
	static Party partySender;//the party of the sender side that is needed for creating the ot communication.
	
	/**
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args) {
		
		
		//Set up the communication with the other side and get the created channel.
		//Channel channel = setCommunication();	
		Channel channel = setCommunicationNotNative();
		
		Date start = new Date();
		OTBatchSender otSender = new OTSemiHonestExtensionSender(partySender,163,1);
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("init ot took " +time + " milis");
		
		
		try {
			
			FastGarbledBooleanCircuit circuit = new ScNativeGarbledBooleanCircuit("NigelAes.txt", CircuitType.FREE_XOR_HALF_GATES, false);
			
			start = new Date();
			//Run the protocol multiple times.
			for(int i=0; i<100;i++){
				
				Date before = new Date();
				//Get the inputs of P1.
				byte[] ungarbledInput = readInputsAsArray();
				
				Date after = new Date();
				time = (after.getTime() - before.getTime());
				System.out.println("read inputs took " +time + " milis");
				//Create Party one with the previous created objects.
				PartyOne p1 = new PartyOne(channel, otSender, circuit);
			
				p1.run(ungarbledInput);
				
				
			}
			end = new Date();
			time = (end.getTime() - start.getTime())/100;
			System.out.println("Yao's protocol party 1 took " +time + " milis");
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Create the inputs of party one from an input file.
	 * @return an Array contains the inputs for party one.
	 */
	private static byte[] readInputsAsArray() {
		File file = new File("AESPartyOneInputs.txt");
		
		Scanner scanner = null;
		try {
			scanner = new Scanner(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			int inputsNumber = scanner.nextInt();
		byte[] inputs = new byte[inputsNumber];
	
		for (int i=0; i<inputsNumber; i++){
			inputs[i] =  (byte) scanner.nextInt();
		}
		
		return inputs;
	}
	
	/**
	 * 
	 * Loads parties from a file and sets up the channel.
	 *  
	 * @return the channel with the other party.
	 */
	@SuppressWarnings("unused")
	private static Channel setCommunication() {
		
		List<PartyData> listOfParties = null;
		
		LoadSocketParties loadParties = new LoadSocketParties("Parties1.properties");
	
		//Prepare the parties list.
		listOfParties = loadParties.getPartiesList();
	
		//Create the communication setup.
		TwoPartyCommunicationSetup commSetup = null;
		try {
			commSetup = new NativeSocketCommunicationSetup(listOfParties.get(0), listOfParties.get(1));
		} catch (DuplicatePartyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	
	
		System.out.print("Before call to prepare\n");
		
		Map<String, Channel> connections = null;
		try {
			connections = commSetup.prepareForCommunication(1, 200000);
		} catch (TimeoutException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
		//Return the channel with the other party. There was only one channel created.
		return (Channel)((connections.values()).toArray())[0];
	}
	
private static Channel setCommunicationNotNative() {
		
		List<Party> listOfParties = null;
		
		LoadParties loadParties = new LoadParties("Parties1.properties");
	
		//Prepare the parties list.
		listOfParties = loadParties.getPartiesList();
		
		//Set the sender party.
		partySender = new Party(listOfParties.get(0).getIpAddress(), 7666);
	
		//Create the communication setup.
		CommunicationSetup commSetup = new CommunicationSetup();
	
		ConnectivitySuccessVerifier naive = new NaiveSuccess();
	
		System.out.print("Before call to prepare\n");
		
		Map<InetSocketAddress, Channel> connections = commSetup.prepareForCommunication(listOfParties, naive, 200000);
			
		//Return the channel with the other party. There was only one channel created.
		return (Channel)((connections.values()).toArray())[0];
	}
}
