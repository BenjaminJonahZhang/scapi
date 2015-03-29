package edu.biu.protocols.yao.primitives;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.exceptions.CircuitFileFormatException;

/**
 * This class creates the cheating recovery circuit.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CheatingRecoveryCircuitCreator {
	private final String circuitFilename;	// Name of cheating recovery circuit.
	private final int inputSize;			// Number of inputs.

	/**
	 * Constructor that sets the parameters.
	 * @param circuitFilename Name of cheating recovery circuit.
	 * @param inputSize Number of inputs.
	 */
	public CheatingRecoveryCircuitCreator(String circuitFilename, int inputSize) {
		this.circuitFilename = circuitFilename;
		this.inputSize = inputSize;
	}
	
	/**
	 * Creates the cheating recovery circuit, if it does not exist.
	 * @return A boolean circuit that represents the cheating recovery circuit.
	 */
	public BooleanCircuit create() {
		//Create the circuit with the given name.
		File circuitFile = new File(circuitFilename);
		//if the circuit file does not exist, create it.
		if (!circuitFile.exists()) {
			//Create an UnlockP1InputCircuitCreator class that creates the file.
			UnlockP1InputCircuitCreator circuitCreator = new UnlockP1InputCircuitCreator(circuitFilename, inputSize);
			try {
				//Create the circuit file.
				circuitCreator.create();
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		}
		
		//Create and return a boolean circuit from the cheating recovery circuit file.
		BooleanCircuit bc = null;
		try {
			//If the file does not exist, throw an exception.
			if (!circuitFile.exists()) {
				throw new IllegalAccessError();
			}
			bc = new BooleanCircuit(circuitFile);
		} catch (CircuitFileFormatException e) {
			throw new IllegalStateException(e); // not allowed!
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e); // not allowed!
		}
		return bc;
	}
}
