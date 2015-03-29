package edu.biu.protocols.yao.offlineOnline.subroutines;

import java.util.HashMap;

import edu.biu.protocols.yao.primitives.CircuitEvaluationResult;
import edu.biu.protocols.yao.primitives.CryptoPrimitives;
import edu.biu.protocols.yao.primitives.CutAndChooseSelection;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;

/**
 * This class computes the circuits and returns the majority output.
 * 
 * By majority output we mean that for each output wire, return the output that most of the circuits outputs.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class MajoriryComputeRoutine implements ComputeCircuitsRoutine {
	private final CutAndChooseSelection selection;					// Indicates which circuit is checked and which is evaluated.
	private final FastGarbledBooleanCircuit[] garbledCircuits;		// The circuits to work on. There is one circuit per thread.
	private HashMap<Integer, byte[]> allOutputs;					// Contains the output of each circuit.
	private byte[] majorityOutput;									// The output of majority of the circuits.
	private int numOfThreads;										// Number of threads to use while computing the circuits.

	/**
	 * A constructor that sets the given parameters.
	 * @param selection Indicates which circuit is checked and which is evaluated.
	 * @param garbledCircuits The circuits to work on. There is one circuit per thread.
	 * @param primitives Contains some primitives objects to use during the protocol.
	 */
	public MajoriryComputeRoutine(CutAndChooseSelection selection, FastGarbledBooleanCircuit[] garbledCircuits, CryptoPrimitives primitives) {
		this.selection = selection;
		this.garbledCircuits = garbledCircuits;
		this.allOutputs = new HashMap<Integer, byte[]>();
		this.majorityOutput = null;
		this.numOfThreads = primitives.getNumOfThreads();
	}
	
	@Override
	public void computeCircuits() throws CheatAttemptException {
		int sizeOfEvalCircuits = selection.evalCircuits().size();
		//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
		if (numOfThreads >0){
			
			//In case the number of thread is less than the number of eval circuits, there is no point to create all the threads.
			//In this case, create only number of threads as the number of eval circuits and assign one circuit to each thread.
			int threadCount = (numOfThreads < sizeOfEvalCircuits) ? numOfThreads : sizeOfEvalCircuits;
			ComputeThread[] threads = new ComputeThread[threadCount];
			
			//Calculate the number of circuit in each thread and the remaining.
			int remain = sizeOfEvalCircuits % threadCount;
			int numOfCircuits =  sizeOfEvalCircuits / threadCount;
			
			//Create the threads and assign to each one the appropriate circuits.
			//The last thread gets also the remaining circuits.
			for (int j=0; j<threadCount; j++){
				if ((j < (threadCount - 1)) || (remain == 0) ){
					threads[j] = new ComputeThread(j*numOfCircuits, (j+1)*numOfCircuits);
				} else {
					threads[j] = new ComputeThread(j*numOfCircuits, sizeOfEvalCircuits);
				}
				//Start all threads.
				threads[j].start();
			}
			
			//Wait until all threads finish their job.
			for (int i=0; i<threadCount; i++) {
				
				try {
					threads[i].join();
				} catch (InterruptedException e) {
					throw new IllegalStateException();
				}
			}
		} else {
			//In case no thread should be created, compute all the circuits directly.
			computeCircuit(0, sizeOfEvalCircuits);
		}
	}
	
	/**
	 * Inner thread class that compute the circuits in a separate thread.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
	 *
	 */
	public class ComputeThread extends Thread{
		
		private int from;				// The first circuit in the circuit list that should be computed.
		private int to;					// The last circuit in the circuit list that should be computed.
		
		/**
		 * Constructor that sets the parameters.
		 * @param from The first circuit in the circuit list that should be computed.
		 * @param to The last circuit in the circuit list that should be computed.
		 */
		public ComputeThread(int from, int to){
			this.from = from;
			this.to = to;
		}
		
		/**
		 * Computes the circuits from the start point to the end point in the circuit list.
		 */
		public void run() {
			computeCircuit(from, to);
		}
	}
	
	/**
	 * Computes the circuits from the start point to the end point in the circuit list.
	 * @param from The first circuit in the circuit list that should be computed.
	 * @param to The last circuit in the circuit list that should be computed.
	 */
	private void computeCircuit(int from, int to) {
		//Get the indices of the eval circuits.
		Object[] indices = selection.evalCircuits().toArray();
		
		//Compute each circuit in the range.
		for (int i=from; i<to; i++){
			try {
				//Get the circuit.
				FastGarbledBooleanCircuit circuit = garbledCircuits[(Integer) indices[i]];
				//Compute it.
				byte[] garbledOutput = circuit.compute();
				//Translate the garbled output.
				byte[] output =  circuit.translate(garbledOutput);
				//Save the boolean output in the outputs map.
				allOutputs.put((Integer) indices[i], output);
			} catch (NotAllInputsSetException e) {
				throw new IllegalStateException();
			} catch (IllegalArgumentException e) {
				// We did not have a correct key for one of the wires for this circuit.
				// Skip to the next circuit.
			}
		}
	}	
	
	@Override
	public CircuitEvaluationResult runOutputAnalysis() {
		//This map will hold for each wire the number of times that each output has been received.
		HashMap<Integer, HashMap<Byte, Integer>> counterMap = new HashMap<Integer, HashMap<Byte,Integer>>();
		int[] outputIndices = garbledCircuits[0].getOutputWireIndices();
		
		// For each circuit and each wire, count how many times each value was received on each wire.
		for (Integer j : selection.evalCircuits()) {
			if (!allOutputs.containsKey(j)) {
				// No output for circuit j, skip.
				continue;
			}
			
			//Get the output of this eval circuit.
			byte[] output = allOutputs.get(j);
			//For each wire index,
			for (Integer w : outputIndices) { 
				Byte wireValue = new Byte(output[w]);
				
				// If this index is first encountered, init the counters map for that label.
				if (!counterMap.containsKey(w)) {
					counterMap.put(w, new HashMap<Byte, Integer>());
				}
				
				// If this value is first encountered for this wire, initialize its counter to zero.
				if (!counterMap.get(w).containsKey(wireValue)) {
					counterMap.get(w).put(wireValue, 0);
				}
				
				// Increase the counter of this value by one.
				Integer currentValue = counterMap.get(w).get(wireValue);
				counterMap.get(w).put(wireValue, currentValue + 1);
			}
		}
		
		//If all output wires didn't get outputs, there is no majority.
		if (counterMap.isEmpty()) {
			// No circuits delivered output, so there is no majority.
			return CircuitEvaluationResult.INVALID_WIRE_FOUND;
		}
		
		//Put the majority output in the majorityOutput array.
		majorityOutput = new byte[outputIndices.length];
		//For each output wire, get the map containing the optional outputs and put in the majority array the output with the highest counter.
		for (Integer w : outputIndices) {
			HashMap<Byte, Integer> counters = counterMap.get(w);
			majorityOutput[w] = getKeyWithMaxValue(counters);
		}
		
		//Returns valid output.
		return CircuitEvaluationResult.VALID_OUTPUT;
	}
	
	/**
	 * Returns the output with the highest counter.
	 * @param map Contains for each output wire all the optional outputs.
	 */
	private Byte getKeyWithMaxValue(HashMap<Byte, Integer> map) {
		
		Byte maxKey = null;
		Integer maxValue = -1;
		
		//For each value in the map, check if it is higher than the maximum.
		//If it is, put it as the maximum.
		for (Byte key : map.keySet()) {
			Integer val = map.get(key);
			if (maxValue < val) {
				maxValue = val;
				maxKey = key;
			}
		}
		
		//Return the value that has the higher counter. 
		return maxKey;
	}
	
	
	/**
	 * Returns the majority output. Meaning, for each output wire, return the output that most of the circuits outputs.
	 */
	public byte[] getOutput() throws CheatAttemptException {
		return majorityOutput;
	}
}
