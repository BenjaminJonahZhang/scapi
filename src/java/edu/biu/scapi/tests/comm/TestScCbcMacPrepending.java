package edu.biu.scapi.tests.comm;

import org.junit.Test;	

import java.security.InvalidKeyException;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.comm.AuthenticatedChannel;
import edu.biu.scapi.comm.PlainChannel;
import edu.biu.scapi.comm.twoPartyComm.PlainTCPSocketChannel;
import edu.biu.scapi.exceptions.InvalidChannelException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.ScCbcMacPrepending;
import edu.biu.scapi.primitives.prf.bc.BcAES;


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
}
