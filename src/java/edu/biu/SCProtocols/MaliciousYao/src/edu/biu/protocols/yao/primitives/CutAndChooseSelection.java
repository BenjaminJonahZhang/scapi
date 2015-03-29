package edu.biu.protocols.yao.primitives;

import java.io.Serializable;
import java.util.Set;
import java.util.TreeSet;

import edu.biu.protocols.yao.common.Preconditions;

/**
 * This class holds the selection of the Cut-And-Choose protocol: 
 * 1. The number of circuit to check 
 * 2. The number of circuits to evaluate.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CutAndChooseSelection implements Serializable {

	private static final long serialVersionUID = 2597162623611175084L;
	
	private final byte[] selection;					//The array that defines which circuit selected to be checked and which to evaluate.
													//If the index of the circuit contain "1" than this circuit should be checked. 
													//Otherwise, the circuit should be evaluated.
	private final int numCircuits;					//The total circuits number.
	private final TreeSet<Integer> checkCircuits;	//The indices of the checked circuits.
	private final TreeSet<Integer> evalCircuits;	//The indices of the evaluated circuits.
	
	/**
	 * A constructor that gets the array that defines which circuit selected to be checked and which to 
	 * evaluate and set the inner members accordingly.
	 */
	public CutAndChooseSelection(byte[] selection) {
		//SEt the selection array and size.
		this.selection = selection;
		this.numCircuits = selection.length;
		
		//Create a set of circuits and push the checked and evaluate circuit to the appropriate place.
		this.checkCircuits = new TreeSet<Integer>();
		this.evalCircuits = new TreeSet<Integer>();

		for (int i = 0; i < numCircuits; i++) {
			// If the index of the circuit contain "1" than this circuit should be checked. 
			// Otherwise, the circuit should be evaluated.
			Preconditions.checkBinary(selection[i]);
			if (1 == selection[i]) {
				checkCircuits.add(i);
			} else {
				evalCircuits.add(i);
			}
		}
	}
	
	/**
	 * returns the selection array that defines which circuit selected to be checked and which to evaluate..
	 */
	public byte[] asByteArray() {
		return this.selection;
	}
	
	/**
	 * Return the set of checked circuits.
	 */
	public Set<Integer> checkCircuits() {
		return checkCircuits;
	}
	
	/**
	 * Return the set of evaluated circuits.
	 */
	public Set<Integer> evalCircuits() {
		return evalCircuits;
	}
}
