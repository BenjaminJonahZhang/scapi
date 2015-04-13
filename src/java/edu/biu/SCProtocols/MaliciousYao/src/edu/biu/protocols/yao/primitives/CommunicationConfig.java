package edu.biu.protocols.yao.primitives;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeoutException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
import edu.biu.scapi.comm.twoPartyComm.NativeChannel;
import edu.biu.scapi.comm.twoPartyComm.NativeSocketCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.TwoPartyCommunicationSetup;
import edu.biu.scapi.exceptions.DuplicatePartyException;

/**
 * This class sets the communication between the parties participate in the protocol. <P>
 * 
 * The type of communication used is native, since it provides better performance than the java implementation. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CommunicationConfig {
	private final String configFilename;			//The name of the file that contains the communication configuration.
	private final PartyData me;						//The current running party.
	private final PartyData otherParty;				//The other party to communicate with.
	
	private Party maliciousOtServer;				//The server data in the malicious OT protocol.
	private Channel[] channels;						//The created channels between the parties.
	TwoPartyCommunicationSetup commSetup = null;

	/**
	 * A constructor that gets the name of the communication configuration file and use it to initialize
	 * the internal class members.
	 * @param configFilename The name of the file that contains the communication configuration.
	 * @throws IOException In case there is a problem to find the malicious OT server.
	 */
	public CommunicationConfig(String configFilename) throws IOException {
		//Get the parties onfirmation from the file. 
		this.configFilename = configFilename;
		LoadSocketParties loadParties = new LoadSocketParties(configFilename);
		this.me = loadParties.getPartiesList().get(0);
		this.otherParty = loadParties.getPartiesList().get(1);
		
		//Initializes the OT server.
		initMaliciousOtSettings();
		this.channels = null;
	}
	
	/**
	 * Does the actual connection between both parties.
	 * @return the created channel.
	 */
	public Channel[] connectToOtherParty(int numberOfChannels) {
		System.out.println("Connecting to the other party...");
		
		Map<String, Channel> connections = null;
		try {
			//Creates the communicationSetup class that manage the communication.
			commSetup = new NativeSocketCommunicationSetup(me, otherParty);
			
			// Connects to the other party. We need one channel between the parties.
			connections = commSetup.prepareForCommunication(numberOfChannels, 200000);
		} catch (DuplicatePartyException e) {
			// If both parties are equal, throw an exception.
			throw new IllegalStateException();
		} catch (TimeoutException e) {
			// If there was a time out, this is wrong state.
			throw new IllegalStateException();
		}
		
		System.out.println("<<<<<<<<<<< DONE >>>>>>>>>>>");
		//Get the created channel.
		Object[] objects = connections.values().toArray();
		channels = new Channel[objects.length];
		for (int i=0; i<objects.length; i++){
			channels[i] = (NativeChannel) objects[i];
		}
		return channels;
	}
	
	/**
	 * Returns the created channel between the parties.
	 */
	public Channel[] getChannels() {
		return channels;
	}
	
	/**
	 * Returns the information about the current running application.
	 */
	public PartyData me() {
		return me;
	}
	
	/**
	 * Returns the information about the other party in the protocol.
	 */
	public PartyData otherParty() {
		return otherParty;
	}
	
	/**
	 * Returns the information about the malicious OT server.
	 */
	public Party maliciousOtServer() {
		return maliciousOtServer;
	}
	
	/**
	 * Initializes the malicious OT server.
	 * Saves the information as Party object and do not communicate to it yet.
	 * @throws IOException if no IP address for the server could be found.
	 */
	private void initMaliciousOtSettings() throws IOException {
		Properties properties = new Properties();
		InetAddress ip = null;
		int port = 0;
        
		//Load the communication file.
        try {
        	properties.load(new FileInputStream(configFilename));
		} catch (FileNotFoundException e) {
			throw new IOException(e);
		}
        
        //Create an ip address of the OT server.
        try {
			ip = InetAddress.getByName(properties.getProperty("MaliciousOTAddress"));
		} catch (UnknownHostException e) {
			throw new IOException(e);
		}
        port = Integer.parseInt(properties.getProperty("MaliciousOTPort"));
        
        //Crate a Party object with the created ip and port.
        this.maliciousOtServer = new Party(ip, port);
	}

	public void close() {
		for (int i=0; i<channels.length; i++){
			channels[i].close();
		}
		commSetup.close();
	}
}
