package edu.biu.protocols.CommitmentWithZkProofOfDifference;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.SecretKey;

import edu.biu.protocols.yao.offlineOnline.primitives.DecommitmentsPackage;
import edu.biu.protocols.yao.primitives.CutAndChooseSelection;
import edu.biu.protocols.yao.primitives.Expector;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
* This protocol is used in the input consistency check. <p>
* It reveals the xor of both committed values without revealing the committed values themselves.<p>
* Meaning, given two commitments: Hcom(s) Hcom(s'), we want to reveal s^s' without revealing s and s'. <P>
* 
* This class represents the receiver of the protocol.
* 
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
public class CmtWithDifferenceReceiver extends CmtWithDifferenceParty {
	//Ids for the w and k commitments.
	private static final int COMMIT_LABEL_W = 1;
	private static final int COMMIT_LABEL_K = 2;
	
	private CutAndChooseSelection selection; 	// Cut and choose selection
	private byte[] w;						 	//Sigma array.
	private SecretKey k;					 	//The key to the encryption scheme that encrypts the cut and choose selection.
	private CmtCCommitmentMsg[][] c;			//The commitment pair for all secrets.
	private byte[][] receivedDeltas;
	private CmtCDecommitmentMessage decomW;		//Decommitment on the sigma array.
	private CmtCDecommitmentMessage decomK;		//Decommitment on the key to the encryption scheme that encrypts the cut and choose selection.
	int n;										//Total number of circuits (eval+chacked)

	/**
	 * A constructor that sets the given parameters and initialize them.
	 * @param selection The cut and choose selection.
	 * @param numCircuits Total number of circuits (eval+chacked)
	 * @param statisticalParameter Indicates how much commitments pairs will be.
	 * @param channel Used to communicate between the parties.
	 * @param random Used to initialize the commitment scheme.
	 * @param hash Used in the commitment scheme.
	 */
	public CmtWithDifferenceReceiver(CutAndChooseSelection selection, int numCircuits, int statisticalParameter, Channel channel, SecureRandom random, CryptographicHash hash) {
		//Call the super constructor to set some of the parameters.
		super(numCircuits, statisticalParameter, channel, random);
		
		this.selection = selection;
		this.c = new CmtCCommitmentMsg[numCircuits][];
		this.receivedDeltas = new byte[numCircuits*2*s][];
		
		//Initialize the commitment scheme.
		initCommitmentScheme(channel, hash);
		
		//Select the sigma array and key for the encryption scheme.
		this.selectK();
		this.selectW();
	}
	
	/**
	 * Select the key for the encryption scheme to use in order to encrypt the cut and choose selection.
	 */
	private void selectK() {
		//Generate a key for the encryption scheme and set it.
		k = enc.generateKey(128);
		try {
			enc.setKey(k);
		} catch (InvalidKeyException e) {
			// Should not happen since the keys was generated using this encrypion object.
			throw new IllegalStateException(e); 
		}
	}
	
	/**
	 * Select the sigma array.
	 */
	private void selectW() {
		w = getRandomString(s);
	}
	
	/**
	 * The setup phase of the protocol.<P>
	 * Generate CmtCCommitmentMsg from w and k.
	 * Generate decommit values for w and k.
	 * Send the created CmtCCommitmentMsg to the committer.
	 * 
	 * @throws IOException
	 */
	public void setup() throws IOException {
		try {
			//Generate CmtCCommitmentMsg from w and k.
			CmtCCommitmentMsg comW = cmtSender.generateCommitmentMsg(cmtSender.generateCommitValue(w), COMMIT_LABEL_W);
			CmtCCommitmentMsg comK = cmtSender.generateCommitmentMsg(cmtSender.generateCommitValue(k.getEncoded()), COMMIT_LABEL_K);
			
			//Generate decommit values for w and k.
			decomW = cmtSender.generateDecommitmentMsg(COMMIT_LABEL_W);
			decomK = cmtSender.generateDecommitmentMsg(COMMIT_LABEL_K);
			
			// Commit to W (cmtSelection) and K (the key for the symmetric enc).
			channel.send(comW);
			channel.send(comK);
		} catch (IllegalArgumentException e) {
			throw new IllegalStateException(e); // should not happen
		} catch (CommitValueException e) {
			throw new IllegalStateException(e); // should not happen
		}
		
		// Send encrypted cut and choose selection.
		channel.send((Serializable) enc.encrypt(new ByteArrayPlaintext(selection.asByteArray())));
	}
	
	/**
	 * Sets the given commitments.
	 * @param commitments The commitments to set.
	 */
	public void receiveCommitment(CmtCCommitmentMsg[][] commitments)  {
		c = commitments;
	}
	
	/**
	 * Sends the decommitment of the key for the encryption scheme so that the other party can decrypt ccSelection.
	 * @throws IOException In case of a problem during the communication.
	 */
	public void revealCutAndChooseSelection() throws IOException {
		// Decommit k so that the other party can decrypt ccSelection.
		channel.send(decomK);
	}
	
	/**
	 * Extracts from the given package the committed value, all randoms used to commit and the decommitment objects.
	 * @param k The index of the checked circuit. The decommitments should be verified against the commitments from the k index.
	 * @param counter The index of the checked circuit in the selection.
	 * @param pack THe package received from the committer that contains the committed value, randoms and decommitments.
	 * @return the committed value, if the decommitments were all verified.
	 * @throws CheatAttemptException In case there was a decommitment that was not verified.
	 */
	public byte[] receiveDecommitment(int k, int counter, DecommitmentsPackage pack) throws CheatAttemptException {
		byte[] x;
		byte[] r;
		
		// Receive the committed value from the package.
		x = pack.getX(counter);
		
		// Receive the random values used to commit (r_1, ..., r_s) from the package.
		r = pack.getR(counter);
		
		// Receive decommitment to c[k] from the package.
		CmtCDecommitmentMessage[] decommitments = pack.getDiffDecommitment(counter, 2*s);
		
		byte[] ri = new byte[x.length];
		
		//Verify each pair of decommitments. 
		//If verified, check that the committed values are indeed r and x^r.
		//Else, throw a cheating exception.
		for (int i = 0; i < s; i++) { // there are s pairs.
			//Get r[i].
			System.arraycopy(r, i*x.length, ri, 0, x.length);
			
			// Compute x ^ r[i].
			byte[] xXorRi = new byte[x.length];
			for (int j = 0; j < xXorRi.length; j++) {
				xXorRi[j] = (byte) (x[j] ^ ri[j]);
			}
			
			// Verify c_k in the i^th place against decom(i).
			CmtCommitValue c0Val = cmtReceiver.verifyDecommitment(c[k][i*2], decommitments[i*2]);
			CmtCommitValue c1Val = cmtReceiver.verifyDecommitment(c[k][i*2+1], decommitments[i*2+1]);
			
			//If verified, convert the committed value to a string.
			String xXorRiDecom = new String(cmtReceiver.generateBytesFromCommitValue(c0Val));
			String riDecom = new String(cmtReceiver.generateBytesFromCommitValue(c1Val));
			
			//Check that the committed value are indeed r and x^r.
			//If not, throw an exception.
			if ( (!xXorRiDecom.equals(new String(xXorRi))) || (!riDecom.equals(new String(ri))) ) {
				throw new CheatAttemptException("decommitment failed!");
			}
		}
		
		return x;
	}
	
	/**
	 * Returns a DifferenceCommitmentReceiverBundle that contains some data of this protocol.
	 * @param j The index of the required commitment.
	 */
	public DifferenceCommitmentReceiverBundle getBundle(int j) {
		return new DifferenceCommitmentReceiverBundle(w, decomW, c[j]);
	}
	
	/**
	 * Verifies the difference by receive the difference of each pair of bundles, send w and than verify the decommitments of the differences.
	 * @param bucket Contains the DifferenceCommitmentCommitterBundle to verify.
	 * @return the committed differences.
	 * @throws IOException In case of a problem during the communication.
	 * @throws CheatAttemptException In case the verification fails.
	 */
	public byte[][] verifyDifferencesBetweenMasks(ArrayList<DifferenceCommitmentReceiverBundle> bucket) throws IOException, CheatAttemptException {
		byte[][] committedDifference = new byte[bucket.size()][];
		
		//Receive the message from the committer.
		Expector expector = new Expector(channel, ProveDiff.class);
		ProveDiff msg = (ProveDiff) expector.receive();
		
		//Receive the committed difference for each secret.
		for (int j = 0; j < bucket.size() - 1; j++) {
			committedDifference[j] = receiveDifference(bucket.get(j), bucket.get(j+1), j, msg);
		}
		
		//Send w to the committer.
		decommitToW();
		
		//Receive the decommitment objects for the received committed differences.
		expector = new Expector(channel, CmtCDecommitmentMessage[].class);
		CmtCDecommitmentMessage[] decommitments = (CmtCDecommitmentMessage[]) expector.receive();
		
		//Verify the received decommitments.
		for (int j = 0; j < bucket.size() - 1; j++) {
			verifyDifference(bucket.get(j), bucket.get(j+1), j, decommitments);
		}
		
		//If all verified, return the committed differences.
		return committedDifference;
	}
	
	/**
	 * Receives the difference of each pair of bundles.
	 * @param b1 The first bundle of the difference.
	 * @param b2 The second bundle of the difference.
	 * @param index The index in the difference package.
	 * @param msg The package to get the commitments.
	 * @return THe committed differences, if there was no cheating.
	 * @throws CheatAttemptException in case the received committed difference is differ from the calculated one.
	 */
	private byte[] receiveDifference(DifferenceCommitmentReceiverBundle b1, DifferenceCommitmentReceiverBundle b2, int index, ProveDiff msg) 
			throws CheatAttemptException {
		//Extract the difference from the committer's package.
		byte[] committedDifference = msg.getCommittedDifference(index);
		
		//Extract the delta from the committer's package (which is the xor of both committed values).
		byte[] delta = msg.getDelta(index);
		
		n = delta.length/s/2;
		
		//For each pair of commitments, calculate the difference using the delta.
		for (int i = 0; i < s; i++) {
			byte[] calculatedDifference = new byte[n];
			
			// CalculatedDifference = delta0[i] ^ delta1[i] = x ^ r_i ^ y ^ p_i ^ r_i ^ p_i = x ^ y.
			for (int j = 0; j < calculatedDifference.length; j++) {
				calculatedDifference[j] = (byte) (delta[2*i*n + j] ^ delta[(2*i+1)*n + j]);
			}
			
			//Check that the calculated value is equal to the received value.
			//If not, throw a cheating exception.
			if (!Arrays.equals(calculatedDifference, committedDifference)) {
				throw new CheatAttemptException("d0_i ^ d1_i != delta for i = " + i + " and k = " + index);
			}
		}
		
		//If all verified, save the delta and return the differences.
		receivedDeltas[index] = delta;
		return committedDifference;
	}
	
	/**
	 * Sends the chosen w.
	 * @throws IOException
	 */
	private void decommitToW() throws IOException {
		// decommit W (cmtSelection).
		channel.send(decomW);
	}
	
	/**
	 * Verifies the decommitments of the differences according to w (cmtSelection).
	 * @param b1 The first bundle of the difference.
	 * @param b2 The second bundle of the difference.
	 * @param k1 The index to use in order to get the decommitments.
	 * @param decommitments An array holds the decommitments.
	 * @throws CheatAttemptException
	 */
	private void verifyDifference(DifferenceCommitmentReceiverBundle b1, DifferenceCommitmentReceiverBundle b2, int k1, 
			CmtCDecommitmentMessage[] decommitments) throws CheatAttemptException {
		
		//GEt both commitments and delta.
		CmtCCommitmentMsg[] c1 = b1.getC();
		CmtCCommitmentMsg[] c2 = b2.getC();
		byte[] delta = receivedDeltas[k1];
		
		//Verify each pair of decommitments.
		//If verified, get both committed values and xor them.
		//Then, check that the xor is equal to the expected from the delta array.
		for (int i = 0; i < s; i++) {
			//Get the decommitments.
			CmtCDecommitmentMessage decomK1 = decommitments[k1*2*s + 2*i];
			CmtCDecommitmentMessage decomK2 =  decommitments[k1*2*s + 2*i + 1];
			
			//Get the index of the decommitments according to w.
			int decomIndex = 2 * i + w[i]; // c0[i] if w[i] == 0 or c1[i] if w[i] == 1.
			CmtCCommitmentMsg comK1 = c1[decomIndex];
			CmtCCommitmentMsg comK2 = c2[decomIndex];
			
			//Verify the decommitments.
			CmtCommitValue cSigmaVal = cmtReceiver.verifyDecommitment(comK1, decomK1);
			CmtCommitValue dSigmaVal = cmtReceiver.verifyDecommitment(comK2, decomK2);
			
			//If verified, get the committed bytes and xor them.
			byte[] cSigma = cmtReceiver.generateBytesFromCommitValue(cSigmaVal);
			byte[] dSigma = cmtReceiver.generateBytesFromCommitValue(dSigmaVal);
			byte[] xor = new byte[cSigma.length];
			for (int j = 0; j < xor.length; j++) {
				xor[j] = (byte) (cSigma[j] ^ dSigma[j]);
			}
			
			//Get the expected xor.
			String expectedXor = new String(delta, decomIndex*n, n);
			
			//Check that the xor is equal to the expected.
			//If not, throw a cheating exception.
			if (!expectedXor.equals(new String(xor))) {
				// Decom(c_i^{W_i}) xor Decom(c_i^{W_i}) != delta_i^{W_i}
				throw new CheatAttemptException("Decom(c_i^{W_i}) xor Decom(c_i^{W_i}) != delta_i^{W_i}");
			}
		}
	}
}