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
package edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSOutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.securityLevel.Malicious;

/**
 * A concrete class for Malicious OT extension sender. <P>
 *  
 * The base OT is done once in the construction time. After that, the transfer function will be always optimized and fast, no matter how much OT's there are.
 * 
 * There are three versions of OT extension: General, Correlated and Random. The difference between them is the way of getting the inputs: <p>
 * In general OT extension both x0 and x1 are given by the user.<p>
 * In Correlated OT extension the user gives a delta array and x0, x1 arrays are chosen such that x0 = delta^x1.<p>
 * In random OT extension both x0 and x1 are chosen randomly.<p>
 * To allow the user decide which OT extension's version he wants, each option has a corresponding input class. <p>
 * The particular OT extension version is executed according to the given input instance; 
 * For example, if the user gave as input an instance of OTExtensionRandomSInput than the random OT Extension will be execute.<p>
 * 
 * NOTE: Unlike a regular implementation the connection is done via the native code and thus the channel provided in the transfer function is ignored.  
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy, Asaf Cohen)
 *
 */
public class OTExtensionMaliciousSender  implements Malicious, OTBatchSender{
	
	private static final String OT_EXTENSION_TYPE_GENERAL = "general";
	private static final String OT_EXTENSION_TYPE_CORRELATED = "correlated";
	private static final String OT_EXTENSION_TYPE_RANDOM = "random";
	
	private long senderPtr; //Pointer that holds the sender pointer in the c++ code.
	
	// This function initializes the sender. It creates sockets to communicate with the sender and attaches these sockets to the receiver object.
	// It outputs the receiver object with communication abilities built in. 
	private native long initOtSender(String ipAddress, int port, int numOfThreads, int numBaseOts, int numOts);
	
	/*
	 * The native code that runs the OT extension as the sender.
	 * @param senderPtr The pointer initialized via the function initOtSender.
	 * @param x0 An array that holds all the x0 values for each of the OT's serially (concatenated).
	 * @param x1 An array that holds all the x1 values for each of the OT's serially (concatenated).
	 * @param delta 
	 * @param numOfOts The number of OTs that the protocol runs (how many strings are inside x0?)
	 * @param bitLength The length (in bits) of each item in the OT. can be derived from |x0|, |x1|, numOfOts
	 * @param version the OT extension version the user wants to use.
	 */
	private native void runOtAsSender(long senderPtr, byte[] x0, byte[]x1, byte[] delta, int numOfOts, int bitLength, String version);
	
	//Deletes the native sender.
	private native void deleteSender(long senderPtr);
	
	/**
	 * A constructor that creates the native sender with communication abilities. It uses the ip address and port given in the party object.<p>
	 * The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	 * THE SENDER ACTS AS THE SERVER!!!
	 * @param bindAddress the ip of this party.
	 * @param listeningPort the port of this party.
	 * @param numBaseOts base ots in the ot extension
	 * @param numOts number of ots to do in parallel
	 */
	public OTExtensionMaliciousSender(String bindAddress, int listeningPort, int numOfThreads, int numBaseOts, int numOts){
	
		// Create the sender by passing the local host address.
		senderPtr = initOtSender(bindAddress, listeningPort, numOfThreads, numBaseOts, numOts);
	}
	
	/**
	 * Default constructor. Initializes the sender by passing the ip address and uses koblitz 163 as a default dlog group.<P>
	 * The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	 * @param bindAddress The address of this party
	 * @param listeningPort the port of this party
	 * @param numOts the number of ots to do in parallel
	 */
	public OTExtensionMaliciousSender(String bindAddress, int listeningPort, int numOts){
		// Create the sender by passing the local host address.
		senderPtr = initOtSender(bindAddress, listeningPort, 1, 190, numOts);
	}

	/**
	 * The overloaded function that runs the protocol.<p>
	 * After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	 * @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	 * @param input The input for the sender specifying the version of the OT extension to run. 
	 * Every call to the transfer function can run a different OT extension version.
	 */
	public OTBatchSOutput transfer(Channel channel, OTBatchSInput input) {
		assert (senderPtr != 0) : "sender pointer was released!";
		
		int numOfOts;

		// In case the given input is general input.
		if (input instanceof OTExtensionGeneralSInput){
			
			//Retrieve the values from the input object.
			byte[] x0 = ((OTExtensionGeneralSInput) input).getX0Arr();
			byte[] x1 = ((OTExtensionGeneralSInput) input).getX1Arr();
			numOfOts = ((OTExtensionGeneralSInput) input).getNumOfOts();
			
			//Call the native function.
			int bitLength = (x0.length/numOfOts)*8;
			runOtAsSender(senderPtr, x0, x1, null, numOfOts, bitLength, OT_EXTENSION_TYPE_GENERAL);
		
			//This version has no output. Return null.
			return null;
			
		//In case the given input is correlated input.
		} else if(input instanceof OTExtensionCorrelatedSInput){
			 
			byte[] delta = ((OTExtensionCorrelatedSInput) input).getDelta();
			
			// Prepare empty x0 and x1 for the output.
			byte[] x0 = new byte[delta.length];
			byte[] x1 = new byte[delta.length];
			
			numOfOts = ((OTExtensionCorrelatedSInput) input).getNumOfOts();
			
			//Call the native function. It will fill x0 and x1.
			runOtAsSender(senderPtr, x0, x1, delta, numOfOts, delta.length/numOfOts*8, OT_EXTENSION_TYPE_CORRELATED);
			
			//Return output contains x0, x1.
			return new OTExtensionSOutput(x0,x1);
		
		//In case the given input is random input.
		} else if(input instanceof OTExtensionRandomSInput){
			 
			numOfOts = ((OTExtensionRandomSInput) input).getNumOfOts();
			int bitLength = ((OTExtensionRandomSInput) input).getBitLength();
			
			//Prepare empty x0 and x1 for the output.
			byte[] x0 = new byte[numOfOts * bitLength/8];
			byte[] x1 = new byte[numOfOts * bitLength/8];
			
			//Call the native function. It will fill x0 and x1.
			runOtAsSender(senderPtr, x0, x1, null, numOfOts, bitLength, OT_EXTENSION_TYPE_RANDOM);
			
			//Return output contains x0, x1.
			return new OTExtensionSOutput(x0,x1);
		
		//If input is not instance of the above inputs, throw Exception.
		} else {
			throw new IllegalArgumentException("input should be an instance of OTExtensionGeneralSInput or OTExtensionCorrelatedSInput or OTExtensionRandomSInput.");
		}
	}

	/**
	 * Deletes the native OT object.
	 * This function MUST be called after the OT is finished!!!
	 * The user of this class SHOULD NOT wait for the finalize() function,
	 * since we don't know when the garbage collector will collect this class. 
	 */ 
	public void releaseResources() {
		//Delete from the dll the dynamic allocation of the receiver.
		if (0 != senderPtr) {
			deleteSender(senderPtr);
			senderPtr = 0;
		}
	}
	
	/**
	 * Deletes the native OT object, ideally the resources were already released explicitly.
	 */
	public void finalize() throws Throwable {
		releaseResources();
	}
	
	static {
		 // Loads the MaliciousOtExtensionJavaInterface jni dll.
		 System.loadLibrary("MaliciousOtExtensionJavaInterface");
	 }
}
