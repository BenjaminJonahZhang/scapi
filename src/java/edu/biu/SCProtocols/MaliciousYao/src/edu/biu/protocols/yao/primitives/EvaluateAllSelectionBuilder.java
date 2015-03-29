package edu.biu.protocols.yao.primitives;

/**
 * This class chooses all circuits to be evaluated.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class EvaluateAllSelectionBuilder implements CutAndChooseSelectionBuilder {

	@Override
	public CutAndChooseSelection build(int numCircuits) {
		//Create an array of size numCircuits and put in "0" in each cell. 
		//"0" means that the circuit in this index is evaluated circuit.
		byte[] selection = new byte[numCircuits];
		for (int i = 0; i < selection.length; i++) {
			selection[i] = 0;
		}
		
		//Create a CutAndChooseSelection object with the selection array.
		return new CutAndChooseSelection(selection);
	}
}
