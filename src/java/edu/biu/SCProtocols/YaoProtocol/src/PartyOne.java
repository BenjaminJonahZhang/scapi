import java.io.IOException;
import java.util.Date;

import edu.biu.scapi.circuits.fastGarbledCircuit.FastCircuitCreationValues;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralSInput;

/**
 * This is an implementation of party one of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class PartyOne {

	OTBatchSender otSender;			//The OT object that is used in the protocol.	
	FastGarbledBooleanCircuit circuit;	//The garbled circuit used in the protocol.
	Channel channel;				//The channel between both parties.
	FastCircuitCreationValues values;
	final int SIZE_OF_BLOCK = 16;
	
	/**
	 * Sets the channel soSender and the fast garbling circuit that the protocol uses.
	 * @param channel
	 * @param otSender
	 * @param circuit
	 */
	public PartyOne(Channel channel, OTBatchSender otSender, FastGarbledBooleanCircuit circuit){
		//Set the given parameters./*
		this.channel = channel;
		this.otSender = otSender;
		this.circuit = circuit;
	}
	
	/**
	 * Runs the protocol.
	 * @param ungarbledInput The input for the circuit, each p1's input wire gets 0 or 1.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 * @throws NotAllInputsSetException 
	 */
	public void run(byte[] ungarbledInput) throws IOException, ClassNotFoundException, CheatAttemptException, InvalidDlogGroupException, NotAllInputsSetException{
		Date startProtocol = new Date();
		
		
		//Garble the circuit. 
		Date start = new Date();
		values = circuit.garble();
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("Garble the circuit took " +time + " milis");
			
		start = new Date();
		//Send garbled tables and the translation table to p2.
		channel.send(circuit.getGarbledTables());
		channel.send(circuit.getTranslationTable());
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("Send garbled tables and translation tables took " +time + " milis");

		start = new Date();
		//Send p1 input keys to p2.
		sendP1Inputs(ungarbledInput);
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("send inputs took " +time + " milis");
		
		
		//Run OT protocol in order to send p2 the necessary keys without revealing any information.
		start = new Date();
		runOTProtocol();
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("run OT took " +time + " milis");
				
		
		Date yaoEnd = new Date();
		long yaoTime = (yaoEnd.getTime() - startProtocol.getTime());
		System.out.println("run party one protocol took " +yaoTime + " milis");
		
		
		
	}

	/**
	 * Sends p1 input keys to p2.
	 * @param ungarbledInput The boolean input of each wire.
	 * @param bs The keys for each wire.
	 * @throws IOException In case there was a problem to send via the channel.
	 */
	private void sendP1Inputs(byte[] ungarbledInput) {
		
		byte[] allInputs = values.getAllInputWireValues();
		
		//get the size of party one inputs
  		int numberOfp1Inputs = 0;
		try {
			numberOfp1Inputs = circuit.getNumberOfInputs(1);
		} catch (NoSuchPartyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
  		
  		byte[] p1Inputs = new byte[numberOfp1Inputs*SIZE_OF_BLOCK];
 	    
  		//Create an array with the keys corresponding the given input.
  		for (int i = 0; i < numberOfp1Inputs; i++) {
  			System.arraycopy(allInputs, (2*i + ungarbledInput[i])*SIZE_OF_BLOCK, p1Inputs, i*SIZE_OF_BLOCK, SIZE_OF_BLOCK);
  		}
 	   
  		//Send the keys to p2.
		try {
			channel.send(p1Inputs);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Runs OT protocol in order to send p2 the necessary keys without revealing any other information.
	 * @param allInputWireValues The keys for each wire.
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 */
	public void runOTProtocol() throws ClassNotFoundException, IOException, CheatAttemptException, InvalidDlogGroupException {
		//Get the indices of p2 input wires.
		int p1InputSize = 0;
		int p2InputSize = 0;		
		
		byte[] allInputWireValues = values.getAllInputWireValues();
		try {
			p1InputSize = circuit.getNumberOfInputs(1);
			p2InputSize = circuit.getNumberOfInputs(2);
			
			
		} catch (NoSuchPartyException e) {
			// Should not occur since the given party number is valid.
		}
		
		
		
		byte[] x0Arr = new byte[p2InputSize * SIZE_OF_BLOCK];
		byte[] x1Arr = new byte[p2InputSize * SIZE_OF_BLOCK];
		
		for (int i=0; i<p2InputSize; i++){
			System.arraycopy(allInputWireValues, p1InputSize*2*SIZE_OF_BLOCK + 2*i*SIZE_OF_BLOCK ,x0Arr , i*SIZE_OF_BLOCK, SIZE_OF_BLOCK);
			System.arraycopy(allInputWireValues, p1InputSize*2*SIZE_OF_BLOCK + (2*i +1)*SIZE_OF_BLOCK , x1Arr, i*SIZE_OF_BLOCK, SIZE_OF_BLOCK);
			
		}
		
		//Create an OT input object with the keys arrays.
		Date start = new Date();
		OTBatchSInput input = new OTExtensionGeneralSInput(x0Arr, x1Arr, p2InputSize);
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("create the ot object " +time + " milis");
		
	
		//Run the OT's transfer phase.
		start = new Date();
		otSender.transfer(null, input);
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("run ot transfer phase " +time + " milis");
		
	}

}
