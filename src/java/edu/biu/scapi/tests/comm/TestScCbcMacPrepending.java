package edu.biu.scapi.tests.comm;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import edu.biu.scapi.comm.AuthenticatedChannel;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.CommunicationSetup;
import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
import edu.biu.scapi.comm.LoadParties;
import edu.biu.scapi.comm.NaiveSuccess;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.comm.PlainChannel;
import edu.biu.scapi.comm.twoPartyComm.NativeSocketCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.PlainTCPSocketChannel;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.comm.twoPartyComm.TwoPartyCommunicationSetup;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.exceptions.InvalidChannelException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.ScCbcMacPrepending;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import junit.framework.AssertionFailedError;


public class TestScCbcMacPrepending {
	public AuthenticatedChannel createAuthenticatedChannel(PlainChannel ch){
		
		Mac mac = null;
		mac = new ScCbcMacPrepending(new BcAES());
		
		/// you could generate the key here and then somehow send it to the other party so the other party uses the same secret key
	    //  SecretKey macKey = SecretKeyGeneratorUtil.generateKey("AES");
	    //  instead, we use a secretKey that has already been agreed upon by both parties:
        byte[] aesFixedKey = new byte[]{-61, -19, 106, -97, 106, 40, 52, -64, -115, -19, -87, -67, 98, 102, 16, 21};
	    SecretKey key = new SecretKeySpec(aesFixedKey, "AES");
	    try {
	    	mac.setKey(key);
    	} 
	    catch (InvalidKeyException e) {
	    	e.printStackTrace();
    	}
	    // decorate the Plain TCP Channel with the authentication
	    AuthenticatedChannel authenChannel = null;
	    try {
	    	authenChannel = new AuthenticatedChannel(ch, mac);
    	} 
	    catch (SecurityLevelException e) {
	    	// This exception will not happen since we chose a Mac that meets the Security Level requirements
	    	e.printStackTrace();
    	}
	    return authenChannel;
    }
	
	@Test(expected = InvalidChannelException.class)  
	public void TestNonInitializedChannelShouldRaiseException() {
		PlainTCPSocketChannel  ptsc = new PlainTCPSocketChannel(); // create not initialized channel 
		createAuthenticatedChannel(ptsc);  // non-initialized channel raises exception
	}
	
	private Channel setCommunication(SocketPartyData partyMe, SocketPartyData partyOther) {
		TwoPartyCommunicationSetup commSetup = null;
		try {
			commSetup = new NativeSocketCommunicationSetup(partyMe, partyOther);
			Map<String, Channel> connections = null;
			connections = commSetup.prepareForCommunication(1, 200000);
			return (Channel)((connections.values()).toArray())[0];			
		} catch (DuplicatePartyException | TimeoutException e1) {
			e1.printStackTrace();
			return null;
		}
	}
	
	private Channel setCommunicationNotNative(Party party0, Party party1)
	{
		List<Party> listOfParties = new LinkedList<Party>(Arrays.asList(party0, party1));
		// Create the communication setup.
		CommunicationSetup commSetup = new CommunicationSetup();
		ConnectivitySuccessVerifier naive = new NaiveSuccess();
		System.out.print("Before call to prepare\n");
		Map<InetSocketAddress, Channel> connections = commSetup.prepareForCommunication(listOfParties, naive, 200000);
		//Return the channel with the other party. There was only one channel created.
		return (Channel)((connections.values()).toArray())[0];
	}
	
	private void testChannel(Channel c, String dataToSend, String expectedDataToRcv) {
		  try{
			  c.send(dataToSend);
			  String res0 = (String) c.receive();
			  assertEquals(expectedDataToRcv, res0);
			  c.close();
		  }
		  catch(IOException | ClassNotFoundException e){
			  fail(e.getMessage());
		  }
	}
	
	@Test
	public void TestNativeConnectionSanity() throws UnknownHostException{
		InetAddress ip = InetAddress.getByName("127.0.0.1");
		final SocketPartyData party0 = new SocketPartyData(ip, 25001);
		final SocketPartyData party1 = new SocketPartyData(ip, 25002);
		final String dataFrom0To1 = "Hi 1 this is 0";
		final String dataFrom1To0 = "Hi 0 this is 1";
		(new Thread() {
			  public void run() {
				  Channel c0 = setCommunication(party0, party1);
				  testChannel(c0, dataFrom0To1 , dataFrom1To0);
			  }}).start();
		Channel c1 = setCommunication(party1, party0);
		testChannel(c1, dataFrom1To0, dataFrom0To1);
	}
	
	@Test
	public void TestNonNativeConnectionSanity() throws UnknownHostException{
		InetAddress ip = InetAddress.getByName("127.0.0.1");
		final Party party0 = new Party(ip, 25003);
		final Party party1 = new Party(ip, 25004);
		final String dataFrom0To1 = "Hi 1 this is 0";
		final String dataFrom1To0 = "Hi 0 this is 1";
		(new Thread() {
			  public void run() {
				  Channel c0 = setCommunicationNotNative(party0, party1);
				  testChannel(c0, dataFrom0To1 , dataFrom1To0);
			  }}).start();
		Channel c1 = setCommunicationNotNative(party1, party0);
		testChannel(c1, dataFrom1To0, dataFrom0To1);
	}
}

