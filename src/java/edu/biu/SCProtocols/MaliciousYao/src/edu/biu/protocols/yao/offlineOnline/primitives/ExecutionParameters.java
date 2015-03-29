package edu.biu.protocols.yao.offlineOnline.primitives;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;

/**
 * This class manages the parameters needed by the execution.<p>
 * 
 * These parameters contain the garbled circuit and boolean circuit used in the protocol, as well as 
 * protocol parameters described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for 
 * Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, section 2.4 [Cut-and-Choose Parameters].
 * 
 * This class contains also the number of evaluated and checked circuits and more. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class ExecutionParameters {
	
	private final BooleanCircuit bc;					// The boolean circuit to evaluate in the protocol.
	private final FastGarbledBooleanCircuit[] gbc;		// Array of garbled circuit from the above boolean circuit.
														// We hold an array of the same circuit because when we use 
														// thread, each one works on a different circuit.
	
	private final int numExecutions;					// N
	private final int statisticalParameter;				// s
	private final int bucketSize;						// B
	private final double evaluationProbability;			// p
	
	private final int numCircuits;						// N * B
	private final int evalCircuits;						// N * B / p
	private final int checkCircuits;					// N * B / p -  N * B
	
	/**
	 * Constructor that sets the parameters.
	 * @param bc
	 * @param mainGbc
	 * @param numExecutions
	 * @param statisticalParameter
	 * @param bucketSize
	 * @param evaluationProbability
	 */
	public ExecutionParameters(BooleanCircuit bc, FastGarbledBooleanCircuit[] mainGbc, int numExecutions, int statisticalParameter, int bucketSize, double evaluationProbability) {
		this.bc = bc;
		this.gbc = mainGbc;
		this.numExecutions = numExecutions; // N
		this.statisticalParameter = statisticalParameter; // s
		this.bucketSize = bucketSize; // B
		this.evaluationProbability = evaluationProbability; // p
		
		this.evalCircuits = numExecutions * bucketSize;
		this.numCircuits = (int) Math.ceil(evalCircuits / evaluationProbability);
		this.checkCircuits = numCircuits - evalCircuits;
	}
	
	/*
	 * Getters and Setters for the class members.
	 */
	
	public FastGarbledBooleanCircuit getCircuit(int i) {
		return gbc[i];
	}
	
	public FastGarbledBooleanCircuit[] getCircuits() {
		
		return gbc;
	}
	
	public int numberOfExecutions() {
		return numExecutions;
	}
	
	public int statisticalParameter() {
		return statisticalParameter;
	}
	
	public int bucketSize() {
		return bucketSize;
	}
	
	public double evaluationProbability() {
		return evaluationProbability;
	}
	
	public int numCircuits() {
		return numCircuits;
	}
	
	public int evalCircuits() {
		return evalCircuits;
	}
	
	public int checkCircuits() {
		return checkCircuits;
	}

	public BooleanCircuit getBooleanCircuit() {
		return bc;
	}
}
