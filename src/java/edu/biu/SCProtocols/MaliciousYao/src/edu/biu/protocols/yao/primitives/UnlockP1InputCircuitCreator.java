package edu.biu.protocols.yao.primitives;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Utility class that creates the cheating recovery circuit file.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class UnlockP1InputCircuitCreator {
	private String filename;			// The name of the file to create.
	
	private int numberOfParties;		// Number of parties of the circuit.
	private int numberOfGates;			// Number of gates in the circuit.
	private int[] numberOfInputWires;	// Number of output wires, for each party.
	private int numberOfOutputWires;	// Number of output wires.
	
	private int masterKeyLabel;			//The wire label of p2 that should enter any gate of the circuit.

	private ArrayList<ArrayList<Integer>> inputLabels;	// Indices of all input wires for each party.
	private ArrayList<Integer> outputLabels;			// Indices of all output wires.
	
	/**
	 * Constructor that sets the parameters and fill internal members.
	 * @param filename The name of the file to create.
	 * @param numInputWiresP1 The number of inputs of P1.
	 */
	public UnlockP1InputCircuitCreator(String filename, int numInputWiresP1) {
		this.filename = filename;		
		this.numberOfParties = 2;
		this.numberOfInputWires = new int[numberOfParties];
		this.numberOfInputWires[0] = numInputWiresP1; // One wire per one input bit of P1
		this.numberOfInputWires[1] = 1; // This is the "master" wire that may or may not unlock P1's input.
		this.numberOfGates = numInputWiresP1; // One AND gate for each input wire of P1.
		this.numberOfOutputWires = numInputWiresP1; // One output wire for each input wire of P1.
		this.masterKeyLabel = numInputWiresP1 + 1;
		this.inputLabels = new ArrayList<ArrayList<Integer>>();
		this.outputLabels = new ArrayList<Integer>();
	}
	
	/**
	 * Creates the circuit recovery file.
	 * @throws IOException If there was a problem writing the file.
	 */
	public void create() throws IOException {
		int currentLabel = 1;
		//Sets the input and output wires indices.
		currentLabel = calculateInputLabels(currentLabel);
		currentLabel = calculateOutputLabels(currentLabel);
		
		BufferedWriter output = new BufferedWriter(new FileWriter(filename));
		
		//Write the number of gates and parties.
		output.write(String.format("%d\n", numberOfGates));
		output.write(String.format("%d\n", numberOfParties));

		// Input wires section.
		for (int i = 0; i < numberOfParties; i++) {
			// The labeling of parties starts from "1".
			int partyLabel = i + 1;
			
			// The party's label, followed by how much input wires it has, followed by the indices of the input wires.
			output.write(String.format("%d %d\n", partyLabel, numberOfInputWires[i]));
			
			// The party's input wires' labels.
			ArrayList<Integer> inputLabelsForThisParty = inputLabels.get(i);
			for (int j = 0; j < inputLabelsForThisParty.size(); j++) {
				output.write(String.format("%d\n", inputLabelsForThisParty.get(j)));
			}
			output.write("\n");
		}

		// Output wires section.
		// The number of output wires, followed by the indices of the output wires.
		output.write(String.format("%d\n", numberOfOutputWires));
		for (int j = 0; j < outputLabels.size(); j++) {
			output.write(String.format("%d\n", outputLabels.get(j)));
		}
		output.write("\n");
		
		// Gates section.
		int numInputsWiresForGate = 2;
		int numOutputsWiresForGate = 1;
		String truthTableANDGate = new String("0001");
		ArrayList<Integer> inputLabelsP1 = inputLabels.get(0);
		
		//For each gate, print the number of inputs of this gate, number of outputs of this gate, 
		//indices of input wires, indices of output wires and the gate truth table. 
		
		for (int i = 0; i < inputLabelsP1.size(); i++) { // inputLabelsP1.size() == outputLabels.size() == numberOfGates
			output.write(String.format("%d %d %d %d %d %s\n",
					numInputsWiresForGate,
					numOutputsWiresForGate,
					inputLabelsP1.get(i), // P1 i^th label has its i^th input bit
					masterKeyLabel, // P2 only label is the "master" label (if it has "1" on the wire, P2 learns P1's input)
					outputLabels.get(i),
					truthTableANDGate));
		}
		
		output.close();
	}
	
	/**
	 * Puts the indices of the input wires in the array.
	 * @param currentLabel first index.
	 * @return the last index.
	 */
	private int calculateInputLabels(int currentLabel) {
		for (int i = 0; i < numberOfParties; i++) {
			ArrayList<Integer> partyLabels = new ArrayList<Integer>();
			for (int j = 0; j < numberOfInputWires[i]; j++) {
				partyLabels.add(new Integer(currentLabel));
				currentLabel++;
			}
			inputLabels.add(partyLabels);
		}
		
		return currentLabel;
	}
	
	/**
	 * Puts the indices of the output wires in the array.
	 * @param currentLabel first index.
	 * @return the last index.
	 */
	private int calculateOutputLabels(int currentLabel) {
		for (int i = 0; i < numberOfOutputWires; i++) {
			outputLabels.add(new Integer(currentLabel));
			currentLabel++;
		}
		
		return currentLabel;
	}
}