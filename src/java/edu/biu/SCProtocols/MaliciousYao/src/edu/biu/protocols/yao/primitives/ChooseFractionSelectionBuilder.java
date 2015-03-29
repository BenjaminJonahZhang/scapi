package edu.biu.protocols.yao.primitives;

import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.protocols.yao.common.Preconditions;

/**
 * This class chooses some of the circuits to be checked and the other circuits to be evaluated.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class ChooseFractionSelectionBuilder implements CutAndChooseSelectionBuilder {

	private final int selectionSize;			// The number of checked circuits.

	/**
	 * A constructor that sets the number of checked circuits.
	 */
	public ChooseFractionSelectionBuilder(int selectionSize) {
		this.selectionSize = selectionSize;
	}
	
	@Override
	public CutAndChooseSelection build(int numCircuits) {
		//check that the number of checked circuit is smaller than the total number of circuits.
		Preconditions.checkArgument(selectionSize < numCircuits);
		
		//Create s the selection array. This array will hold "1" for each checked circuit and "0" for each evaluated circuit.
		byte[] selection = new byte[numCircuits];
		ArrayList<Integer> circuitSelectionPool = new ArrayList<Integer>();
		
		for (int j = 0; j < numCircuits; j++) {
			selection[j] = 0; // All indices are initially not selected to be checked.
			circuitSelectionPool.add(new Integer(j)); // All indices are initially in the selection pool.
		}
		
		// Select a circuit randomly from the list of circuits selectionSize times.
		for (int i = 0; i < selectionSize; i++) {
			SecureRandom rand = new SecureRandom();

			//select an index.
			// ArrayList is dynamic so every time we remove() an element
			// the size is changed (circuits.size() gets smaller).
			int selectedIndex = rand.nextInt(circuitSelectionPool.size()-1);
			int selectedCircuit = (int) circuitSelectionPool.remove(selectedIndex);

			// Set the selectCircuit's index in the selection byte array to be checked (put "1" in this index).
			selection[selectedCircuit] = 1;
		}
		
		//Create a CutAndChooseSelection object with the selection array.
		return new CutAndChooseSelection(selection);
	}
}
