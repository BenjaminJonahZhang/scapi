package edu.biu.scapi.tests.BooleanCircuit;

import java.io.File;
import java.io.FileNotFoundException;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.exceptions.CircuitFileFormatException;

public class TestBooleanCircuit {

	public static void main(String[] args) {
		BooleanCircuit circuit;
		try {
			circuit = new BooleanCircuit(new File("/home/moriya/scapi/src/java/edu/biu/scapi/tests/BooleanCircuit/NigelAes.txt"));
			circuit.write("/home/moriya/scapi/src/java/edu/biu/scapi/tests/BooleanCircuit/NigelAesOutput.txt");
		} catch (FileNotFoundException | CircuitFileFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	}
}
