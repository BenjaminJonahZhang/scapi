package edu.biu.protocols.CommitmentWithZkProofOfDifference;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.protocols.yao.offlineOnline.primitives.DecommitmentsPackage;
import edu.biu.protocols.yao.primitives.CutAndChooseSelection;
import edu.biu.protocols.yao.primitives.Expector;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * This protocol is used in the input consistency check. <p>
 * It reveals the xor of both committed values without revealing the committed values themselves.<p>
 * Meaning, given two commitments: Hcom(s) Hcom(s'), we want to reveal s^s' without revealing s and s'. <P>
 * 
 * This class represents the committer of the protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CmtWithDifferenceCommitter extends CmtWithDifferenceParty {
	private int n;													//The total number of circuits. (checked + eval)
	private byte[][] x;												//The actual committed values.
	private CmtCCommitmentMsg wCommitment;							//Commitment on the sigma array.
	private CmtCCommitmentMsg kCommitment;							//Commitment on the key to the encryption scheme that encrypts the cut and choose selection.
	private SymmetricCiphertext cutAndChooseSelectionCiphertext;	//The ciphertext of the cut and choose selection.
	private long commitmentId = 0;									//id for the commitment scheme. each commitment has its own id.
	private SC[] c;													//Holds the commitment pair for each actual committed value.
	private SecretKey k;											//The key to the encryption scheme that encrypts the cut and choose selection.
	private byte[] w;												//The sigma array received from the receiver.

	/**
	 * A constructor that sets the given parameters and initialize them.
	 * @param x The actual committed values.
	 * @param numCircuits The total number of circuits. (checked + eval)
	 * @param statisticalParameter Indicates how much commitments pairs will be.
	 * @param channel Used to communicate between the parties.
	 * @param random Used to initialize the commitment scheme.
	 * @param hash Used in the commitment scheme.
	 */
	public CmtWithDifferenceCommitter(byte [][] x, int numCircuits, int statisticalParameter, Channel channel, SecureRandom random, CryptographicHash hash) {
		//Call the super constructor to set some of the parameters.
		super(numCircuits, statisticalParameter, channel, random);
		
		//Initialize the commitment scheme.
		initCommitmentScheme(channel, hash);
		
		this.n = x[0].length;
		
		//Check the lengths of the secrets.
		for (int i = 0; i < x.length; i++) {
			if (x[i].length != n) {
				throw new IllegalArgumentException("all secrets must be of the same length!");
			}
		}
		
		this.x = x;
		this.c = new SC[numCircuits];
	}
	
	/**
	 * The setup phase of the protocol. Receives from the receiver the wCommitment, kCommitment and cutAndChooseSelectionCiphertext.
	 * @throws IOException In case of a problem during the receiving.
	 */
	public void setup() throws IOException {
		//Receive wCommitment and kCommitment.
		Expector cmtExpector = new Expector(channel, CmtCCommitmentMsg.class);
		wCommitment = (CmtCCommitmentMsg) cmtExpector.receive();
		kCommitment = (CmtCCommitmentMsg) cmtExpector.receive();
		
		//Receive the cutAndChooseSelectionCiphertext.
		Expector ciphertextExpector = new Expector(channel, SymmetricCiphertext.class);
		cutAndChooseSelectionCiphertext = (SymmetricCiphertext) ciphertextExpector.receive();
	}
	
	/**
	 * Creates all commitment pairs for all secrets and puts the created commitments in a big array
	 * @return an array contains all created commitments.
	 */
	public CmtCCommitmentMsg[][] getCommitments() {
		//Alocate space for all commitments.
		CmtCCommitmentMsg[][] commitments = new CmtCCommitmentMsg[numCircuits][];
		
		//For each secret, create a SC object that generate the commitment pairs  and put the commitment in the above array.
		for (int i = 0; i < numCircuits; i++) {
			c[i] = new SC(cmtSender, x[i], commitmentId, s);
			commitmentId = c[i].getNextAvailableCommitmentId();
			commitments[i] =  c[i].getCommitments(); // 2*s commitments.
		}
		return commitments;
	}
	
	/**
	 * Receives the cut and choose selection according to the following steps:
	 * 1. Receive kDecommitment, verifies it. 
	 * 2. If not verified, throw a cheating exception. 
	 * 3. If verified, convert the committed value into a key.
	 * 4. Decrypt the cutAndChooseSelectionCiphertext to get the cut and choose selection.
	 * @return The cut and choose selection, if everything went good.
	 * @throws IOException In case of a problem during the communication.
	 * @throws CheatAttemptException If the received kDecommitment was not verified.
	 */
	public CutAndChooseSelection receiveCutAndChooseSelection() throws IOException, CheatAttemptException {
		//Receive the kDecommitment.
		Expector cmtExpector = new Expector(channel, CmtCDecommitmentMessage.class);
		CmtCDecommitmentMessage kDecommitment = (CmtCDecommitmentMessage) cmtExpector.receive();
		
		//Verify the kDecommitment.
		CmtCommitValue kVal = cmtReceiver.verifyDecommitment(kCommitment, kDecommitment);
		
		//If was not verified, throw a cheating exception.
		if (null == kVal) {
			throw new CheatAttemptException("decommitment of k failed!");
		}
		
		//Else, convert the committed value to a key to the encryption scheme.
		byte[] kBytes = cmtReceiver.generateBytesFromCommitValue(kVal);
		k = new SecretKeySpec(kBytes, "");
		try {
			enc.setKey(k);
		} catch (InvalidKeyException e) {
			throw new CheatAttemptException(e.getMessage());
		}
		
		//Decrypt the cut and choose selection and return it.
		ByteArrayPlaintext selectionArray = (ByteArrayPlaintext) enc.decrypt(cutAndChooseSelectionCiphertext);
		return new CutAndChooseSelection(selectionArray.getText());
	}
	
	/**
	 * Puts in the given package the required secret, all randoms for this secret and all decommitments objects.
	 * @param k The index of the required secret.
	 * @param counter The placed in the package were the secret, randoms and secommitments should be placed.
	 * @param pack The package that will be sent to the other party and should be filled woth the secret, randoms and decryptions.
	 */
	public void getDecommit(int k, int counter, DecommitmentsPackage pack) {
		
		// Put x_k in the package.
		pack.setX(counter, x[k]);
		
		// Put all randoms r_1, ..., r_s in the package.
		pack.setR(counter, c[k].getR());
		
		// Put decommitments to c[k] in the package.
		CmtCDecommitmentMessage[] decommitments = c[k].getDecommitments();
		pack.setDiffDecommitments(counter, decommitments);
	}
	
	/**
	 * Returns a DifferenceCommitmentCommitterBundle that contains some data of this protocol.
	 * @param k The index of the required secret and related commitments.
	 */
	public DifferenceCommitmentCommitterBundle getBundle(int k) {
		//Create a bundle with the secret, its pairs of commitments and the wCommitment.
		return new DifferenceCommitmentCommitterBundle(x[k], c[k], wCommitment);
	}
	
	/**
	 * Proves the difference by committing to the difference of each pair of bundles, receive w and than send the decommitments of the differences.
	 * @param bucket Contains the DifferenceCommitmentCommitterBundle to prove.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public void proveDifferencesBetweenMasks(ArrayList<DifferenceCommitmentCommitterBundle> bucket) throws IOException, ClassNotFoundException, CheatAttemptException {
		//Commit on each pair of bundles.
		ProveDiff msg = new ProveDiff(bucket.size() - 1, n, s);
		for (int j = 0; j < bucket.size() - 1; j++) {
			commitToDifference(bucket.get(j), bucket.get(j+1), j, msg);
		}
		
		//Send the commitments to the other party.
		channel.send(msg);
		
		//receive w.
		receiveW();
		
		//Send the decommitments of the committed differences.
		CmtCDecommitmentMessage[] decommitments = new CmtCDecommitmentMessage[(bucket.size() - 1)*s*2];
		for (int j = 0; j < bucket.size() - 1; j++) {
			proveDifference(bucket.get(j), bucket.get(j+1), decommitments, j);
		}
		channel.send(decommitments);
	}
	
	/**
	 * Commits on the difference of each pair of bundles.
	 * @param b1 The first bundle to use.
	 * @param b2 The second bundle to use.
	 * @param index The index in the difference package.
	 * @param msg The package to put the cmmitments.
	 */
	private void commitToDifference(DifferenceCommitmentCommitterBundle b1, DifferenceCommitmentCommitterBundle b2, int index, ProveDiff msg) {
		byte[] x1 = b1.getX();
		byte[] x2 = b2.getX();
		SC c1 = b1.getC();
		SC c2 = b2.getC();
		
		// Send the difference x[k1] ^ x[k2] (but not the masks themselves).
		byte[] committedDifference = new byte[n];
		for (int j = 0; j < n; j++) {
			committedDifference[j] = (byte) (x1[j] ^ x2[j]);
		}
		msg.setCommittedDifference(index, committedDifference);
		
		// P1 sends 2*s shares to P2.
		// P2 must choose a challenge W (the choose).
		//P1 sends the xor of both committed values. 
		byte[] delta = new byte[2*s*n];
		for (int i = 0; i < s; i++) {
			// Xor loop.
			for (int j = 0; j < n; j++) {
				delta[2*i*n + j] = (byte) (x1[j] ^ c1.getR(i)[j] ^ x2[j] ^ c2.getR(i)[j]); // x ^ r_i ^ y ^ p_i
				delta[(2*i+1)*n + j] = (byte) (c1.getR(i)[j] ^ c2.getR(i)[j]); // r_i ^ p_i
				
			}
		}

		msg.setDelta(index, delta);
	}
	
	/**
	 * Receives w from the receiver and verifies it.<P>
	 * W is the sigma array used to get the decommitments.
	 * @throws IOException In case of a problem during the communication.
	 */
	private void receiveW() throws IOException {
		//Receive w.
		Expector cmtExpector = new Expector(channel, CmtCDecommitmentMessage.class);
		CmtCDecommitmentMessage wDecommitment = (CmtCDecommitmentMessage) cmtExpector.receive();
		
		//Verify w.
		CmtCommitValue wVal = cmtReceiver.verifyDecommitment(wCommitment, wDecommitment);
		w = cmtReceiver.generateBytesFromCommitValue(wVal);
	}
	
	/**
	 * Gets the decommitments of the differences according to the received w (sigma array).
	 * @param b1  The first bundle to use.
	 * @param b2  The second bundle to use.
	 * @param decommitments An array to store the decommitments.
	 * @param index The index to use in order to store the decommitments.
	 */
	private void proveDifference(DifferenceCommitmentCommitterBundle b1, DifferenceCommitmentCommitterBundle b2, CmtCDecommitmentMessage[] decommitments, int index) {
		Preconditions.checkNotNull(w);
		//Get both decommitments of each pair.
		for (int i = 0; i < s; i++) {
			decommitments[2*s*index + 2*i] = b1.getC().getDecom(i, w[i]);
			decommitments[2*s*index + 2*i + 1] = b2.getC().getDecom(i, w[i]);
		}
	}
}
