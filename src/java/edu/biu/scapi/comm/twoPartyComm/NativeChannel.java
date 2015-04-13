package edu.biu.scapi.comm.twoPartyComm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.logging.Level;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.generals.Logging;

public class NativeChannel implements Channel{

	/**
	 * A channel has a state. It can be either NOT_INIT,CONNECTING or READY.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
	 */
	public static enum State {
		
		NOT_INIT,
		CONNECTING,
		READY
	}
	
	private State state;						// The state of the channel.
	
	private SocketPartyData me;
	private SocketPartyData other; 
	
	private long sendSocketPtr;
	private long receiveSocketPtr;
	
	private boolean isClosed;
	
	private native long initSendSocket(String address, int port);
	private native void send(long sendSocketPtr, byte[] data);
	private native byte[] receive(long receiveSocketPtr);
	private native boolean closeSockets(long sendSocketPtr, long receiveSocketPtr);
	private native void enableNagle(long sendSocketPtr, long receiveSocketPtr);
	
	NativeChannel(SocketPartyData me, SocketPartyData other) {
		this.me = me; 
		this.other = other;
		
		sendSocketPtr = 0;
		receiveSocketPtr = 0;
		
	}
	
	@Override
	public void send(Serializable data) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();  
	    ObjectOutputStream oOut  = new ObjectOutputStream(bOut);
		oOut.writeObject(data);  
		oOut.close();
		
		byte[] msgBytes = bOut.toByteArray();
		send(sendSocketPtr, msgBytes);
		
	}

	@Override
	public Serializable receive() throws ClassNotFoundException, IOException {
		byte[] data =  receive(receiveSocketPtr);
		ByteArrayInputStream iInput = new ByteArrayInputStream(data);
		ObjectInputStream ois = new ObjectInputStream(iInput);
		
		return (Serializable) ois.readObject();
	}

	@Override
	public void close() {
		isClosed = closeSockets(sendSocketPtr, receiveSocketPtr);
		
	}

	@Override
	public boolean isClosed() {
		
		return isClosed;
	}
	
	/**
	 * Sets the state of the channel. 
	 */
	public void setState(State state) {
		this.state = state; 
		
	}
	
	/**
	 * Returns the state of the channel. 
	 */
	State getState() {
		
		return state;
	}
	
	/**
	 * Returns if the send socket is connected.
	 */
	boolean isSendConnected(){
		
		if(sendSocketPtr != 0){
			
			return true;
		
		} else{
			return false;
		}
	}
	
	/** 
	 * Connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to 
	 * is not up yet then we sleep for a while and try again until the connection is established. 
	 * This is done by the {@link SocketCommunicationSetup} which keeps trying until it succeeds or a timeout has 
	 * been reached.<p>		
	 * After the connection has succeeded the output stream is set for the send function.
	 * @throws IOException 
	 */
	void connect()  {
		
		//try to connect
		Logging.getLogger().log(Level.INFO, "Trying to connect to " + other.getIpAddress().getHostAddress()+ " on port " + other.getPort());
		
		//create and connect the socket. Cannot reconnect if the function connect fails since it closes the socket.
		sendSocketPtr = initSendSocket(other.getIpAddress().getHostAddress(), other.getPort());
		
		if(sendSocketPtr != 0){
			
			Logging.getLogger().log(Level.INFO, "Socket connected");
				
			//After the send socket is connected, need to check if the receive socket is also connected.
			//If so, set the channel state to READY.
			setReady();
		}	
		
	}
	
	/**
	 * This function sets the channel state to READY in case both send and receive sockets are connected.
	 */
	protected void setReady() {
		if(sendSocketPtr != 0 && receiveSocketPtr != 0){
			
			//set the channel state to READY
			state = State.READY;
			isClosed = false;
			Logging.getLogger().log(Level.INFO, "state: ready " + toString());				
			
		}
	}
	public void setReceiveSocket(long receiveSocket) {
		this.receiveSocketPtr = receiveSocket;
		//After the receive socket is connected, need to check if the send socket is also connected.
		//If so, set the channel state to READY.
		setReady();
	}
	
	static {	 
		 //load the NTL jni dll
		 System.loadLibrary("MaliciousOtExtensionJavaInterface");
	}

	public void enableNage() {
		enableNagle(sendSocketPtr, receiveSocketPtr);
		
	}

}
