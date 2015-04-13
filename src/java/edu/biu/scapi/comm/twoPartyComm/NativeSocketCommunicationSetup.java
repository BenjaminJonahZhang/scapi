package edu.biu.scapi.comm.twoPartyComm;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import org.apache.commons.exec.TimeoutObserver;
import org.apache.commons.exec.Watchdog;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.generals.Logging;

public class NativeSocketCommunicationSetup implements TwoPartyCommunicationSetup, TimeoutObserver{
	
	protected boolean bTimedOut = false; 							//Indicated whether or not to end the communication.
	protected Watchdog watchdog;										//Used to measure times.
	protected boolean enableNagle = false;							//Indicated whether or not to use Nagle optimization algorithm.
	protected NativeSocketListenerThread listeningThread;					//Listen to calls from the other party.
	protected int connectionsNumber;									//Holds the number of created connections. 
	protected SocketPartyData me;									//The data of the current application.
	protected SocketPartyData other;								//The data of the other application to communicate with.
	
	private Map<String, Channel> connectionsMap;
	
	private native void initSystem();
	private native void closeSystem();
	
	/**
	 * A constructor that set the given parties.
	 * @param me The data of the current application.
	 * @param party The data of the other application to communicate with.
	 * @throws DuplicatePartyException 
	 */
	public NativeSocketCommunicationSetup(PartyData me, PartyData party) throws DuplicatePartyException{
		//Both parties should be instances of SocketPArty.
		if (!(me instanceof SocketPartyData) || !(party instanceof SocketPartyData)){
			throw new IllegalArgumentException("both parties should be instances of SocketParty");
		}
		this.me = (SocketPartyData) me;
		this.other = (SocketPartyData) party;
		
		//Compare the two given parties. If they are the same, throw exception.
		int partyCompare = this.me.compareTo(other);
		if(partyCompare == 0){
			throw new DuplicatePartyException("Another party with the same ip address and port");
		}
		connectionsNumber = 0;
	//	initSystem();
	}
	
	/**  
	 * Initiates the creation of the actual sockets connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.
	 * @throws TimeoutException in case a timeout has occurred before all channels have been connected.
	 */
	@Override
	public Map<String, Channel> prepareForCommunication(String[] connectionsIds, long timeOut) throws TimeoutException {		
		
		//Start the watch dog with the given timeout.
		watchdog = new Watchdog(timeOut);
		//Add this instance as the observer in order to receive the event of time out.
		watchdog.addTimeoutObserver(this);
		watchdog.start();
		
		//Establish the connections.
		establishConnections(connectionsIds);
		
		//Verify that all connections have been connected.
		verifyConnectingStatus();
		
		//If we already know that all the connections were established we can stop the watchdog.
		watchdog.stop();
			
		//In case of timeout, throw a TimeoutException
		if (bTimedOut){
			throw new TimeoutException("timeout has occurred");
		}
		
		//Set Nagle algorithm.
		if (enableNagle)
			enableNagleInChannels();
		
		//Update the number of the created connections.
		connectionsNumber += connectionsMap.size();
		
		return connectionsMap;
		
	}

	@Override
	public Map<String, Channel> prepareForCommunication(int connectionsNum, long timeOut) throws TimeoutException {
		//Prepare the connections Ids using the default implementation, meaning the connections are numbered 
		//according to their index. i.e the first connection's name is "1", the second is "2" and so on.
		String[] names = new String[connectionsNum];
		for (int i=0; i<connectionsNum; i++){
			names[i] = Integer.toString(connectionsNumber++);
		}
		
		//Call the other prepareForCommunication function with the created ids.
		return prepareForCommunication(names, timeOut);
	}

	/**
	 * This function does the actual creation of the communication between the parties.<p>
	 * A connected channel between two parties has two sockets. One is used by P1 to send messages and p2 receives them,
	 * while the other used by P2 to send messages and P1 receives them.
	 * 
	 * The function does the following steps:
	 * 1. Calls the connector.createChannels function that creates a channel for each connection.
	 * 2. Start a listening thread that accepts calls from the other party.
	 * 3. Calls the connector.connect function that calls each channel's connect function in order to connect each channel to the other party.
	 * @param connectionsIds The names of the requested connections. 
	 *
	 */
	private void establishConnections(String[] connectionsIds) {
		
		//Calls the connector to create the channels.
		NativeChannel[] channels = createChannels(connectionsIds, false);
		
		if (!bTimedOut){
			//Create a listening thread with the created channels.
			//The listening thread receives calls from the other party and set the creates sockets as the receiveSocket of the channels.
			createListener(channels);
			listeningThread.start();
		}
		
		//Calls the connector to connect each channel.
		connect(channels);
		
	}
	
	private NativeChannel[] createChannels(String[] connectionsIds,	boolean checkIdentity) {
		//Initiate the channels map.
		connectionsMap = new HashMap<String,Channel>();
		
		int size = connectionsIds.length;
		//Create an array to hold the created channels.
		NativeChannel[] channels = new NativeChannel[size];
		
		//Create the number of channels as requested, give them the names in connectionsIds and set them in the establishedConnections object.
		for (int i=0; i<size; i++){
			//Create a channel.
			channels[i] = new NativeChannel(me, other);
		
			//Set to NOT_INIT state.
			channels[i].setState(NativeChannel.State.NOT_INIT);
			// Add the channel to the map.
			connectionsMap.put(connectionsIds[i], channels[i]);
		}
		
		return channels;
	}
	
	private void connect(NativeChannel[] channels) {
		//For each channel, call the connect function until the channel is actually connected.
		for (int i=0; i<channels.length && !bTimedOut; i++){
			
			//while connection has not been stopped by owner and connection has failed.
			while(!channels[i].isSendConnected() && !bTimedOut){
				
				//Set the state to connecting.
				channels[i].setState(NativeChannel.State.CONNECTING);
				Logging.getLogger().log(Level.INFO, "state: connecting " + channels[i].toString());
				
				//Try to connect.
				channels[i].connect();
				
			}
				
			Logging.getLogger().log(Level.INFO, "End of securing thread run" + channels[i].toString());
		}
	}


	protected void createListener(NativeChannel[] channels) {
		listeningThread = new NativeSocketListenerThread(channels, me);
	}

	@Override
	public void enableNagle(){
		//Set to true the boolean indicates whether or not to use the Nagle optimization algorithm. 
		//For Cryptographic algorithms is better to have it disabled.
		this.enableNagle  = true;
	}
	
	/**
	 * This function is called by the infrastructure of the Watchdog if the previously set timeout has passed. (Do not call this function).
	 */
	public void timeoutOccured(Watchdog w) {

		Logging.getLogger().log(Level.INFO, "Timeout occured");
		
		//Timeout has passed, set the flag.
		bTimedOut = true;
	
		//Further stop the listening thread if it still runs. Similarly, it sets the flag of the listening thread to stopped.
		if(listeningThread != null)
			listeningThread.stopConnecting();
		
		stopConnecting();
		
		
		
	}
	
	private void verifyConnectingStatus() {
		//Wait until the thread has been stopped or all the channels are connected.
		while(!bTimedOut && !areAllConnected()){
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {

				Logging.getLogger().log(Level.FINEST, e.toString());
			}
		}
	}
	
	/** 
	 * @return true if all the channels are in READY state, false otherwise.
	 */
	private boolean areAllConnected() {
		//Set an iterator for the connection map.
		Collection<Channel> c = connectionsMap.values();
		Iterator<Channel> itr = c.iterator();
		
		NativeChannel plainChannel;
		//Go over the map and check if all the connections are in READY state.
		while(itr.hasNext()){
			plainChannel = (NativeChannel)itr.next();
		       if(plainChannel.getState()!=NativeChannel.State.READY){
		    	   return false;
		       }
		}
		
		return true;
	}

	/**
	* Sets the flag bStopped to false. In the run function of this thread this flag is checked - 
	* if the flag is true the run functions returns, otherwise continues.
	*/
	public void stopConnecting(){
	
		//Set the flag to true.
		bTimedOut = true;
		
		Channel channel;
		String id;
			
		//Set an iterator for the connection map.
		Iterator<String> iterator = connectionsMap.keySet().iterator();
		
		//Go over the map and close all connection.
		while(iterator.hasNext()){ 
			//Get the channel.
			id = iterator.next();
			channel = connectionsMap.get(id);
		       
			//Close the channel.
			channel.close();
		}
		
		//Remove all channels from the map.
		connectionsMap.clear();
	}
	
	/**
	 * This implementation has nothing to close besides the sockets (which are being closed by the channel instances).
	 */
	public void close() {
	//	closeSystem();
	}
	
	/**
	 * Enables Nagle's algorithm.
	 */
	public void enableNagleInChannels() {
		NativeChannel NativeChannel;
		Channel channel;
		String id;
		
		//Set an iterator for the connection map.
		Iterator<String> iterator = connectionsMap.keySet().iterator();
		
		//Go over the map and enable/disable each channel with the Nagle algorithm.
		while(iterator.hasNext()){
			
			//Get the channel.
			id = iterator.next();
			channel = connectionsMap.get(id);
			
			//Check if the channel is a plain tcp channel. Otherwise there is no point for the Nagle algorithm.
			if(channel instanceof NativeChannel){
				NativeChannel = (NativeChannel) channel;
				
				//Enable nagle.
				NativeChannel.enableNage();			
			}	    	   	    
		}	
		
	}
	
	static {	 
		 //load the NTL jni dll
		 System.loadLibrary("MaliciousOtExtensionJavaInterface");
	}

}
