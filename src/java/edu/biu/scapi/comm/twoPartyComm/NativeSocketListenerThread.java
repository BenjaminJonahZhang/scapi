package edu.biu.scapi.comm.twoPartyComm;

import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;

public class NativeSocketListenerThread extends Thread {
	
	protected NativeChannel[] channels;	//All connections between me and the other party. The received sockets of each channel should be set when accepted. 
	private SocketPartyData me;
	private long serverSocket;
	protected boolean bStopped = false;			//A flag that indicate if to keep on listening or stop.
	
	private native long initReceiveSocket(String address, int port);
	private native long accept(long serverSocket);
	private native void close(long serverSocket);
	
	/**
	* A constructor that open the server socket.
	* @param channels the channels that should be set with receive socket.
	* @param me the data of the current application.
	* @param partyAdd The address to listen on.
	*/
	NativeSocketListenerThread(NativeChannel[] channels, SocketPartyData me) {
	
		this.channels = channels;
		this.me = me;
		serverSocket = initReceiveSocket(me.getIpAddress().getHostAddress(), me.getPort());
	}

	/**
	* Sets the flag bStopped to false. In the run function of this thread this flag is checked - 
	* if the flag is true the run functions returns, otherwise continues.
	*/
	void stopConnecting(){
	
		//Set the flag to true.
		bStopped = true;
	}

	/**
	* This function is the main function of the SocketListenerThread. Mainly, we listen and accept valid connections 
	* as long as the flag bStopped is false or until we have got as much connections as we should.<p>
	* We use the ServerSocketChannel rather than the regular ServerSocket since we want the accept to be non-blocking. 
	* If the accept function is blocking the flag bStopped will not be checked until the thread is unblocked.  
	*/
	public void run() {
	
		//Set the state of all channels to connecting.
		int size = channels.length;
		for (int i=0; i<size; i++){
		
			channels[i].setState(NativeChannel.State.CONNECTING);
		}
		
		int i=0;
		//Loop for listening to incoming connections and make sure that this thread should not stopped.
		while (i < size && !bStopped) {
		
			Logging.getLogger().log(Level.INFO, "Trying to listen "+ me.getIpAddress());
			
			//Use the server socket to listen to incoming connections.
			long receiveSocket = accept(serverSocket);
		
			//If there was no connection request wait a second and try again.
			if(receiveSocket == 0){
				try {
					Thread.sleep (1000);
				} catch (InterruptedException e) {
				
					Logging.getLogger().log(Level.INFO, e.toString());
				}
			//If there was an incoming request, check it.
			} else{
				
				channels[i].setReceiveSocket(receiveSocket);
				
				//Increment the index of incoming connections.
				i++;
				
			}
		}
	
		Logging.getLogger().log(Level.INFO, "End of listening thread run");
		
		//After accepting all connections, close the thread.
		close(serverSocket);
			
	}
	
	static {	 
		 //load the NTL jni dll
		 System.loadLibrary("MaliciousOtExtensionJavaInterface");
	}
}
