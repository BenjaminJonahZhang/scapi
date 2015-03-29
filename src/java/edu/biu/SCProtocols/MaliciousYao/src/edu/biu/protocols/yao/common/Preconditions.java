package edu.biu.protocols.yao.common;

/**
 * This class provides some pre-checks that can be used in the protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class Preconditions {
	
	/**
	 * Checks if the given expression is true. 
	 * If not, the function throws an exception.
	 * @param expression To check.
	 */
	public static void checkArgument(boolean expression) {
		//In case the expression is false, throw an exception.
		if(!expression) {
			throw new IllegalArgumentException();
		}
	}
	
	/**
	 * Checks if the given expression is not zero. 
	 * If the expression is zero, the function throws an exception.
	 * @param expression To check.
	 */
	public static void checkNotZero(int expression) {
		checkArgument(0 != expression);
	}
	
	/**
	 * Checks if the given expression is not null. 
	 * If the expression is null, the function throws an exception.
	 * @param expression To check.
	 */
	public static void checkNotNull(Object ref) {
		checkArgument(null != ref);
	}
	
	/**
	 * Checks if the given index is between the given min and max values.
	 * If not, the function throws an exception.
	 * @param i The index to check.
	 * @param min The minimum value that the index can be.
	 * @param max The maximum value that the index can be.
	 */
	public static void checkIntegerInRange(int i, int min, int max) {
		checkArgument((min <= i) && (i <= max));
	}
	
	/**
	 * Checks if the given index is below the given upper bound.
	 * If not, the function throws an exception.
	 * @param i The index to check.
	 * @param upperBound The maximum value that the index can be.
	 */
	public static void checkIndexInRange(int i, int upperBound) {
		checkIntegerInRange(i, 0, upperBound - 1);
	}
	
	/**
	 * Checks if the given value is a binary value (e.g. 0/1).
	 * If not, the function throws an exception.
	 * @param i The value to check.
	 */
	public static void checkBinary(int i) {
		checkIntegerInRange(i, 0, 1);
	}
}
