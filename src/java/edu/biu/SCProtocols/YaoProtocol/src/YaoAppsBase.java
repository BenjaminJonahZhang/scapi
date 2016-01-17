package edu.biu.SCProtocols.YaoProtocol.src;

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
import edu.biu.scapi.circuits.fastGarbledCircuit.ScNativeGarbledBooleanCircuitNoFixedKey;
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

@SuppressWarnings("deprecation")
public abstract class YaoAppsBase {
	
	static Party partySender; //the party of the sender side that is needed for creating the ot communication.
	static YaoConfig yao_config;
	static Channel channel;
	
	protected static void init(int party_number) {
		yao_config = YaoConfig.readYaoConfiguration("propertiesFiles/yao.properties");
		// set up the communication with the other side and get the created channel.
		// channel channel = setCommunication();
		String net_config_file = (party_number==1)? yao_config.party_1_net_config : yao_config.party_2_net_config;
		channel = setCommunicationNotNative(net_config_file);
	}
	
	protected static FastGarbledBooleanCircuit create_circuit() {
		//return new ScNativeGarbledBooleanCircuit(yao_config.circuit_file, CircuitType.FREE_XOR_HALF_GATES, false);
		return new ScNativeGarbledBooleanCircuitNoFixedKey(yao_config.circuit_file, true);
	}
	/**
	 * Create the inputs of party one from an input file.
	 * @return an Array contains the inputs for party one.
	 */
	protected static byte[] readInputsAsArray(String inputFileName) {
		Date before = new Date();
		File file = new File(inputFileName);
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
		System.out.println("read inputs took " + (new Date().getTime() - before.getTime()) + " milis");
		return inputs;
	}

	/**
	 * 
	 * Loads parties from a file and sets up the channel.
	 *  
	 * @return the channel with the other party.
	 */
	protected static Channel setCommunication() {
		
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
	
	protected static Channel setCommunicationNotNative(String partyPropertiesFileName) {
		List<Party> listOfParties = null;
		LoadParties loadParties = new LoadParties(partyPropertiesFileName); 	
		//Prepare the parties list.
		listOfParties = loadParties.getPartiesList();
		
		//Set the sender party.
		partySender = new Party(listOfParties.get(0).getIpAddress(), 7666);
	
		//Create the communication setup.
		CommunicationSetup commSetup = new CommunicationSetup();
	
		ConnectivitySuccessVerifier naive = new NaiveSuccess();
			
		Map<InetSocketAddress, Channel> connections = commSetup.prepareForCommunication(listOfParties, naive, 200000);
			
		//Return the channel with the other party. There was only one channel created.
		return (Channel)((connections.values()).toArray())[0];
	}
	
}
