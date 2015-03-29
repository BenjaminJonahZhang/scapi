package edu.biu.protocols.yao.primitives;

/**
 * This interface declares the CutAndChoose selection builder which is actually the method to select the circuits 
 * (to be checked of evaluated). <p>
 * 
 * There are several types of CutAndChoose selections, each one of them should have a related builder class. 
 * All builder classes should implement this interface and the build function in it.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public interface CutAndChooseSelectionBuilder {
	
	/**
	 * Selects the circuits to be checked or evaluated.
	 * @param numCircuits The total circuits number.
	 * @return The selection.
	 */
	public CutAndChooseSelection build(int numCircuits);
}
