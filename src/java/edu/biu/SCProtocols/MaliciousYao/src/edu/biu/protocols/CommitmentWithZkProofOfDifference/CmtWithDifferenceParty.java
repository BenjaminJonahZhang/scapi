package edu.biu.protocols.CommitmentWithZkProofOfDifference;

import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash.CmtSimpleHashReceiver;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.OpenSSLCTREncRandomIV;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;
import edu.biu.scapi.tools.Factories.PrfFactory;

/**
 * This class is an abstract class the gather parameters that common for the committer and verifier of the difference
 * protocol in the input consistency protocol. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
abstract class CmtWithDifferenceParty {
	protected int numCircuits;				//The total number of circuits. (checked + eval)
	protected int s;						//Security parameter. Indicates how much commitments pairs will be.
	protected CmtCommitter cmtSender;		//The committer in the commitment scheme.
	protected CmtReceiver cmtReceiver;		//The receiver in the commitment scheme.
	protected SecureRandom random;			//Source of randomness to use.
	protected Channel channel;				//Used to communicate between the channels.
	protected SymmetricEnc enc;				//Used to encrypt and decrypt the cut and choose selection.

	/**
	 * A constructor that sets the parameters and initialize the encryption scheme.
	 * @param numCircuits The total number of circuits. (checked + eval)
	 * @param statisticalParameter A security parameter. Indicates how much commitments pairs will be.
	 * @param channel Used to communicate between the channels.
	 * @param random Source of randomness to use.
	 * @throws IllegalArgumentException In case numCircuits == 0
	 */
	CmtWithDifferenceParty(int numCircuits, int statisticalParameter, Channel channel, SecureRandom random) throws IllegalArgumentException {
		//Sets the parameters and initialize the encryption scheme.
		this.numCircuits = numCircuits;
		if (0 == numCircuits) {
			throw new IllegalArgumentException("x must contain at least one string!");
		}
		
		this.s = statisticalParameter;
		this.channel = channel;
		this.random = random;
		this.initEncryptionScheme();
	}
	
	/**
	 * Initialize the encryption scheme.
	 */
	private void initEncryptionScheme() {
		//Create a pseudo random permutation.
		PseudorandomPermutation prp;
		try {
			prp = (PseudorandomPermutation) PrfFactory.getInstance().getObject("AES", "OpenSSL");
		} catch (FactoriesException e) {
			throw new IllegalArgumentException();
		}

		//Use the created prp in order to create an encryption scheme.
		this.enc = new OpenSSLCTREncRandomIV(prp);
	}
	
	/**
	 * Returns random array where each cell contains 0/1 value.
	 * @param n The size of the required array.
	 * @return
	 */
	protected byte[] getRandomString(int n) {
		//Create the array.
		byte[] randomString = new byte[n];
		
		//Put in each cell 0/1.
		for (int i = 0; i < randomString.length; i++) {
			randomString[i] = (byte) random.nextInt(2);
		}
		return randomString;
	}
	
	/**
	 * Initializes the commitment scheme using the given parameters.
	 * @param channel  Used to communicate between the parties.
	 * @param hash The hash function to use in the commitment.
	 * @throws IllegalArgumentException
	 */
	protected void initCommitmentScheme(Channel channel, CryptographicHash hash) throws IllegalArgumentException {
		try {
			this.cmtSender = new CmtSimpleHashCommitter(channel, hash, random, hash.getHashedMsgSize()); 
			this.cmtReceiver = new CmtSimpleHashReceiver(channel, hash, hash.getHashedMsgSize()); 
		} catch (Exception e) {
			// It does not matter what the exception is, we throw Illegal Argument Exception
			throw new IllegalArgumentException(e.getMessage());
		}
	}
}