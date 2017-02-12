package edu.biu.scapi.comm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;

public class FasterTCPChannel extends PlainChannel {
	
	public static class FasterMessage implements Serializable {
		private static final long serialVersionUID = -3417234887693230863L;
		
		private byte[] data = null;
		
		public FasterMessage(byte[] data) {
			this.data = data;
		}
		
		public void setData(byte[] data) {
			this.data = data;
		}
		
		public byte[] getData() {
			return data;
		}
	}
	
	private Socket socket = new Socket();
	private InetSocketAddress socketAddress;
	private DataOutputStream outStream;
	private DataInputStream inStream;
	
	/**
	 * Creates a channel given the IP address and the port to connect to. 
	 * @param ipAddress other end's IP address
	 * @param port other end's port
	 */
	FasterTCPChannel(InetAddress ipAddress, int port) {
		
		socketAddress = new InetSocketAddress(ipAddress, port);
	}
	
	/**
	 * Creates a channel given an InetSocketAddress.
	 * @param socketAddress other end's InetSocketAddress
	 */
	FasterTCPChannel(InetSocketAddress socketAddress) {

		this.socketAddress = socketAddress;
	}
	
	/**
	 * Creates a channel given a Party and an established socket
	 * Allows us to bypass scapi's communication establishment and replace the channel type.
	 * @param party other the other party the channel connects 
	 * @param socket the socket between this party and the other
	 */
	public FasterTCPChannel(Party party, Socket socket) {
		this.socketAddress = new InetSocketAddress(party.getIpAddress(), party.getPort());
		this.setSocket(socket);
	}

	@Override
	public void send(Serializable data) throws IOException {
		byte[] msgBytes = null;
		
		if (!(data instanceof FasterMessage)) {
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		    ObjectOutputStream oOut  = new ObjectOutputStream(bOut);
			oOut.writeObject(data);
			oOut.close();
			msgBytes = bOut.toByteArray();
			outStream.writeBoolean(false); // is not faster
		} else {
			FasterMessage msg = (FasterMessage) data;
			msgBytes = msg.getData();
			outStream.writeBoolean(true); // is faster
		}
		outStream.writeInt(msgBytes.length);
		outStream.write(msgBytes);
	}

	@Override
	public Serializable receive() throws ClassNotFoundException, IOException {
		boolean isFaster = inStream.readBoolean();
		int msgSize = inStream.readInt();
		byte[] msg = new byte[msgSize];
		int bytesRead = inStream.read(msg, 0, msgSize);
		
		if (bytesRead < msgSize) {
			throw new IOException("did not read all bytes...");
		}
		
		if (isFaster) {
			return new FasterMessage(msg);
		}
		
		ByteArrayInputStream iInput = new ByteArrayInputStream(msg);
		ObjectInputStream ois = new ObjectInputStream(iInput);
		return (Serializable) ois.readObject();
	}
	
	/**
	 * Closes the socket and all other used resources.
	 */
	@Override
	public void close() {
		if(socket != null) {
			try {
				outStream.close();
				inStream.close();
				socket.close();
			} catch (IOException e) {
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
		}
	}

	@Override
	public boolean isClosed() {
		return (socket.isInputShutdown() || 
				socket.isOutputShutdown() || 
				socket.isClosed() || 
				!socket.isConnected());
	}
	
	/** 
	 * Connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to 
	 * is not up yet then we sleep for a while and try again until the connection is established. This is done by the SecuringConnectionThread which keeps trying
	 * until it succeeds or a timeout has been reached.<p>		
	 * After the connection has succeeded the input and output streams are set for the send and receive functions.
	 * @return true when connected
	 * @throws IOException 
	 */
	@Override
	protected boolean connect() throws IOException {
		
		//try to connect
		Logging.getLogger().log(Level.INFO, "Trying to connect to " + socketAddress.getAddress() + " on port " + socketAddress.getPort());
		
		//create and connect the socket. Cannot reconnect if the function connect fails since it closes the socket.
		socket = new Socket(socketAddress.getAddress(), socketAddress.getPort());
			
		if(socket.isConnected()){
			try {
				Logging.getLogger().log(Level.INFO, "Socket connected");
				outStream = new DataOutputStream(socket.getOutputStream());
				inStream = new DataInputStream(socket.getInputStream());
			} catch (IOException e) {
				Logging.getLogger().log(Level.FINEST, e.toString());
			}
		}
		
		return true;
	}
	
	/**
	 * Returns if the socket is connected
	 */
	@Override
	protected boolean isConnected() {
		if(socket!=null) {
			return socket.isConnected();
		} else {
			return false;
		}
	}
	
	/**
	 * Sets the socket and the input and output streams. If the user uses this function it means that 
	 * the connect function will not be called and thus, the streams should be set here.
	 * @param socket the socket to set
	 * 		
	 */
	void setSocket(Socket socket) {
		this.socket = socket;
		
		try {
			//set t he input and output streams
			outStream = new DataOutputStream(socket.getOutputStream());
			inStream = new DataInputStream(socket.getInputStream());
		} catch (IOException e) {

			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}
	
	/**
	 * Return the underlying socket. Used only internally.
	 * @return the underlying socket
	 */
	Socket getSocket(){
		return socket;
	}
}
