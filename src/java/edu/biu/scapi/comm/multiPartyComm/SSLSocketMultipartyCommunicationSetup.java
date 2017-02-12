package edu.biu.scapi.comm.multiPartyComm;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import edu.biu.scapi.comm.multiPartyComm.SocketMultipartyCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.PlainTCPSocketChannel;
import edu.biu.scapi.comm.twoPartyComm.SSLSocketChannel;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.comm.twoPartyComm.TwoPartySocketConnector;
import edu.biu.scapi.generals.Logging;

/**
 * This class implements a communication between multiple parties using SSL sockets.<p>
 * It derives the {@link SocketMultipartyCommunicationSetup} class since the implementation is equal except the channel type.
 * This class creates an {@link SSLSocketChannel} while the SocketMultipartyCommunicationSetup creates a {@link PlainTCPSocketChannel}.<p>
 * 
 * In order to create an sslSocket you should have an {@link SSLContext} which should be loaded with the key store and trust store. 
 * The keyStore contains the certificate that should be sent to the other party, in SCAPI the default name is "scapiKeystore".
 * The trustStore contains the certificate that should be received from the other party, in SCAPI the default name as "scapiCacerts".
 * This loading is done once in the constructor of this class and is passed to the {@link SSLSocketMultipartyListenerThread} and to each {@link SSLSocketChannel}. 
 * This factory is used to send the certificate of this application.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SSLSocketMultipartyCommunicationSetup extends SocketMultipartyCommunicationSetup{

	private SSLContext sc;	//Loaded with the keyStore and trustStore and used to get the SSLSocketFactory and SSLServerSocketFactory from.
	
	/**
	 * Constructor that gets the data of all parties and the password to the keyStore and trustStore.
	 * @param parties The data of all the parties.
	 * @param storePass The password to the keyStore and trustStore.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLSocketMultipartyCommunicationSetup(List<PartyData> parties, String storePass) throws SSLException {
		//Call the other constructor with the default key sotre and trust store names.
		this(parties, "scapiKeystore.jks", "scapiCacerts.jks", storePass);
	}
	
	/**
	 * Constructor that gets the data of all parties, the names of the key store and trust store and the password to them.
	 * @param parties The data of all the parties.
	 * @param keyStoreName Name of the keyStore file.
	 * @param trustStoreName Name of the trustStore file.
	 * @param storePass The password to the keyStore and trustStore.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLSocketMultipartyCommunicationSetup(List<PartyData> parties, String keyStoreName, String trustStoreName, String storePass) throws SSLException{
		
		//Creating the SSL Context to get the socket factories from.
		try {
			
			//Loading the trust store containing the certificate that should be received from the other party.
			KeyStore trustStore = KeyStore.getInstance("JKS");
			trustStore.load(new FileInputStream(trustStoreName), storePass.toCharArray());
	        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
	        tmf.init(trustStore);
	         
	        //Loading the key store containing the certificate that should be sent to the other party.
	        KeyStore keyStore = KeyStore.getInstance("JKS");
	        keyStore.load(new FileInputStream(keyStoreName), storePass.toCharArray());
	        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	        kmf.init(keyStore, storePass.toCharArray());
	         
	        //Create the SSL context and initialize it with the created key store and trust store.
	        sc = SSLContext.getInstance("TLSv1.2");
	        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
		
	        //construct the other parameters of the class.
	        doConstruct(parties);
		} catch (Exception e) {
			Logging.getLogger().log(Level.SEVERE, e.toString());
			throw new SSLException(e.getCause());
		} 
	}
	
	@Override
	/**
	 * Create a connector between me and the given party. 
	 * The created connector will create an SSL channels, as needed in this communication setup class.
	 */
	protected TwoPartySocketConnector createConnector(PartyData party) {
		TwoPartySocketConnector connector = new TwoPartySocketConnector(me, party, sc.getSocketFactory());
		return connector;
	}

	@Override
	/**
	 * Creates a listener that listens for incoming calls from SSL sockets.
	 */
	protected SSLSocketMultipartyListenerThread createListener(Map<SocketPartyData, PlainTCPSocketChannel[]> channelsPerParty) {
		return new SSLSocketMultipartyListenerThread(channelsPerParty, me, sc.getServerSocketFactory());
	}
}
