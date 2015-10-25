/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

package edu.biu.scapi.comm.twoPartyComm;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.logging.Level;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import edu.biu.scapi.generals.Logging;

/**
 * This class represents a concrete channel in the Decorator Pattern used to create Channels. This channel ensures using of SSL communication.<P>
 * In order to enforce the right usage of the Channel class we will restrict the ability to instantiate one, 
 * only to classes within the Two party Communication Layer's package. This means that the constructor of the channel will be 
 * unreachable from another package. However, the send, receive and close functions will be declared public, therefore 
 * allowing anyone holding a channel to be able to use them.<p>
 *  
 * This class derives the {@link PlainTCPSocketChannel} since the functionality is identical to the regular channel except the creation of the socket that here is an ssl socket.
 * The creation of the socket is done using the {@link SSLSocketFactory} that is given in the constructors of the class.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SSLSocketChannel extends PlainTCPSocketChannel{
	
	private SSLSocketFactory ssf; //Used to create the ssl sockets.
	
	/**
	 * A constructor that create the socket address according to the given ip and port and set the state of this channel to not ready.
	 * @param ipAddress other party's IP address.
	 * @param port other party's port.
	 * @param ssf The socketFactory used to create the ssl socket.
	 */
	SSLSocketChannel(InetAddress ipAddress, int port, SSLSocketFactory ssf, boolean checkIdentity, SocketPartyData me) {
		
		this(new InetSocketAddress(ipAddress, port), ssf, checkIdentity, me);
	}
	
	/**
	 * A constructor that set the given socket address and set the state of this channel to not ready.
	 * @param socketAddress other end's InetSocketAddress
	 * @param ssf The socketFactory used to create the ssl socket.
	 */
	SSLSocketChannel(InetSocketAddress socketAddress, SSLSocketFactory ssf, boolean checkIdentity, SocketPartyData me) {
		
		super(socketAddress, checkIdentity, me);
		this.ssf = ssf;
	}
	
	@Override
	protected boolean connect()  {
		//try to connect
		Logging.getLogger().log(Level.INFO, "Trying to connect to " + socketAddress.getAddress() + " on port " + socketAddress.getPort());
		
		//create the SSL socket. Cannot reconnect if the function connect fails since it closes the socket.
		try {
			sendSocket = ssf.createSocket(socketAddress.getAddress(), socketAddress.getPort());
			
			//Set the enables protocol to TLS 1.2.
			String [] protocols = new String[1];
			protocols[0] = "TLSv1.2";
			((SSLSocket)sendSocket).setEnabledProtocols(protocols);
			
			//Set the enables cipherSuits.
			String [] cipherSuits = new String[2];
			cipherSuits[0] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
			cipherSuits[1] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
			((SSLSocket)sendSocket).setEnabledCipherSuites(cipherSuits);
			
			//Configure the socket to use client mode when handshaking.
			((SSLSocket)sendSocket).setUseClientMode(true);
			((SSLSocket)sendSocket).addHandshakeCompletedListener(new SSLHandshakeCompletedListener(this));
			
			//There are cases where there is a need to check the identity of an incoming connection. 
			//For example, in case of multiparty communication each party should check who is the party that connect.
			//For that reason, we send the identity of the current application after getting the socket. 
			if (checkIdentity){
				sendIdentity();
			}
			
			//Start the handshaking.
			((SSLSocket)sendSocket).startHandshake();
			
		} catch (IOException e) {
			//This exception can be thrown every time the socket didn't manage to connect. 
			//This is fine because the channel tries to connect until it succeed.
			Logging.getLogger().log(Level.FINEST, e.toString());
			return false;
		}
		return true;
	
	}

	/**
	 * Listens until the SSL handshake is complete.
	 * Then, sets the channel as the receive socket.
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
	 */
	class SSLHandshakeCompletedListener implements HandshakeCompletedListener{

		SSLSocketChannel channel;
		SSLHandshakeCompletedListener(SSLSocketChannel channel){
			this.channel = channel;
		}
		
		/**
		 * After the send socket has been created, set its outputStream to this ObjectOutputStream and call setReady().
		 */
		@Override
		public void handshakeCompleted(HandshakeCompletedEvent arg0) {
			
			Logging.getLogger().log(Level.INFO, "Socket connected");
			try {
				channel.outStream = new ObjectOutputStream(arg0.getSocket().getOutputStream());
				
			} catch (IOException e) {
				
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//After the send socket is connected, need to check if the receive socket is also connected.
			//If so, set the channel state to READY.
			setReady();
		}
	}
	
		
}
