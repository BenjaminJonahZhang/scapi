import java.io.IOException;
import java.io.Serializable;
import java.util.Date;

import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledTablesHolder;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralRInput;

/**
 * This is an implementation of party two of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class PartyTwo {

	OTBatchReceiver otReceiver;			//The OT object that used in the protocol.	
	FastGarbledBooleanCircuit circuit;		//The garbled circuit used in the protocol.
	Channel channel;					//The channel between both parties.
	byte[] p1Inputs;
	byte[] p2Inputs;
	
	/**
	 * Sets the channel, otReceiver and the fast garbling circuit that the protocol uses.
	 * @param channel
	 * @param otReceiver
	 * @param circuit
	 */
	public PartyTwo(Channel channel, OTBatchReceiver otReceiver, FastGarbledBooleanCircuit circuit){
		//Set the given parameters.
		this.channel = channel;
		this.otReceiver = otReceiver;
		this.circuit = circuit;
	}
	
	/**
	 * Runs the protocol.
	 * @param ungarbledInput The input for the circuit, each p2's input wire gets 0 or 1.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 */
	public void run(byte[] ungarbledInput) throws CheatAttemptException, ClassNotFoundException, IOException, InvalidDlogGroupException {
		Date startProtocol = new Date();//the starting time of the protocol
		
		//Receive the garbled circuit and translation table.
		Date start = new Date();
		receiveCircuit();
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("Receive garbled tables and translation tables and p1 inpustfrom p1 took " +time + " milis");
		
		//receive the input keys of party one.
		start = new Date();
		receiveP1Inputs();
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("Receive P1 input keys" +time + " milis");
		
		
		//Run OT protocol in order to get the necessary keys without revealing any information.
		start = new Date();
		OTBatchROutput output = runOTProtocol(ungarbledInput);
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("run OT took " +time + " milis");
		
		//Compute the circuit.
		start = new Date();
		byte[] circuitOutput = computeCircuit(output);
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("compute the circuit took " +time + " milis");
		
		Date yaoEnd = new Date();
		long yaoTime = (yaoEnd.getTime() - startProtocol.getTime());
		System.out.println("run one protocol took " +yaoTime + " milis");
		
		//Just for printing, can be removed in case no printing is needed.
		int outputSize = circuit.getOutputWireIndices().length;
		
		for (int i=0; i<outputSize;i++){
			System.out.print(circuitOutput[i]);
		}
		System.out.println();
		
	}

	/**
	 * Receive the circuit's garbled tables and translation table.
	 * @throws CheatAttemptException
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	void receiveCircuit() throws CheatAttemptException, ClassNotFoundException, IOException {
		//Receive garbled tables.
		Serializable msg = channel.receive();
		if (!(msg instanceof GarbledTablesHolder)){
			throw new CheatAttemptException("the received message should be an instance of GarbledTablesHolder");
		}
		GarbledTablesHolder garbledTables = (GarbledTablesHolder) msg;
	
		//Receive translation table.
		msg = channel.receive();
		if (!(msg instanceof byte[])){
			throw new CheatAttemptException("the received message should be an instance of byte[]");
		}
		byte[] translationTable = (byte[]) msg;
			
		//Set garbled tables and translation table to the circuit.
		circuit.setGarbledTables(garbledTables);
		circuit.setTranslationTable(translationTable);
	}
	
	/**
	 * Receives party one input.
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	void receiveP1Inputs() throws ClassNotFoundException, IOException, CheatAttemptException {
		//Receive the inputs as an ArrayList.
		Serializable msg = channel.receive();
		if (!(msg instanceof byte[])){
			throw new CheatAttemptException("the received message should be an instance of ArrayList<SecretKey>");
		}
		p1Inputs = (byte[]) msg;
		
	}
	
	/**
	 * Run OT protocol in order to get party two input without revealing any information.
	 * @param sigmaArr Contains a byte indicates for each input wire which key to get.
	 * @return The output from the OT protocol, party tw oinputs.
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 */
	OTBatchROutput runOTProtocol(byte[] sigmaArr) throws ClassNotFoundException, IOException, CheatAttemptException, InvalidDlogGroupException {
		//Create an OT input object with the given sigmaArr.
		OTBatchRInput input = new OTExtensionGeneralRInput(sigmaArr, 128);
		
		//Run the Ot protocol.
		return otReceiver.transfer(channel, input);
	}
	
	/**
	 * Compute the garbled circuit.
	 * @param otOutput The output from the OT protocol, which are party two inputs.
	 * @return 
	 */
	private byte[] computeCircuit(OTBatchROutput otOutput) {
		
		//Get the output of the protocol.
		byte[] p2Inputs = ((OTOnByteArrayROutput)otOutput).getXSigma();
		
  	   	//copy the inputs of p1 and p2 to a single array.
	    byte[] allInputs= new byte[p1Inputs.length+p2Inputs.length];
	    System.arraycopy(p1Inputs, 0, allInputs, 0, p1Inputs.length);
	    System.arraycopy(p2Inputs, 0, allInputs, p1Inputs.length, p2Inputs.length);
  		
  		//Set the input to the circuit.
		circuit.setInputs(allInputs);
		
		//Compute the circuit.
  		byte[] garbledOutput = null;
		try {
			garbledOutput = circuit.compute();
		} catch (NotAllInputsSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//Translate the resulted computed keys.
  		byte[] circuitOutput = circuit.translate(garbledOutput);
  		return circuitOutput;
	}
}
