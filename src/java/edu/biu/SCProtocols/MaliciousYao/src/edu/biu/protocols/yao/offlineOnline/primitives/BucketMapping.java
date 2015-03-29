package edu.biu.protocols.yao.offlineOnline.primitives;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import edu.biu.protocols.yao.common.Preconditions;
import edu.biu.protocols.yao.primitives.SeededRandomnessProvider;

/**
 * This class manage the mapping of bundles into buckets. <p>
 * 
 * Meaning, given an item, this class returns the id of the bucket where the item should be placed.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class BucketMapping {
	
	private ArrayList<Integer> shuffledCircuits;
	private int[][] buckets;
	private Map<Integer, Integer> mapping;

	/**
	 * A constructor that does the mapping of circuits numbers into buckets.
	 * @param circuits the ids of the circuits.
	 * @param seed A random byte array to use in order to shuffle the circuits.
	 * @param numBuckets The number of required buckets.
	 * @param bucketSize The number of circuit in each bucket.
	 */
	public BucketMapping(ArrayList<Integer> circuits, byte[] seed, int numBuckets, int bucketSize) {
		//Check that the number of circuit equals to numBuckets * bucketSize.
		Preconditions.checkArgument(circuits.size() == numBuckets * bucketSize);
		
		//Create a new array that contains the circuits, then shuffle it.
		this.shuffledCircuits = new ArrayList<Integer>(circuits);
		Collections.shuffle(shuffledCircuits, SeededRandomnessProvider.getSeededSecureRandom(seed));
		
		this.buckets = new int[numBuckets][bucketSize];
		this.mapping = new HashMap<Integer, Integer>();
		//Put in the buckets arrays and the mapping map the indices of the shuffled circuits.
		//The indices are taken from the shufflesCircuits array.
		for (int bucketIndex = 0; bucketIndex < numBuckets; bucketIndex++) {
			for (int i = 0; i < bucketSize; i++) {
				int circuit = shuffledCircuits.get(bucketIndex * bucketSize + i);
				buckets[bucketIndex][i] = circuit;
				mapping.put(circuit, bucketIndex);
			}
		}
	}
	
	/**
	 * A constructor that does the mapping of circuits numbers into buckets.
	 * @param circuits the ids of the circuits.
	 * @param seed A random byte array to use in order to shuffle the circuits.
	 * @param numBuckets The number of required buckets.
	 * @param bucketSize The number of circuit in each bucket.
	 */
	public BucketMapping(Set<Integer> circuits, byte[] seed, int numBuckets, int bucketSize) {
		this(new ArrayList<Integer>(circuits), seed, numBuckets, bucketSize);
	}
	
	/**
	 * Returns the bucket id of the given circuit.
	 * @param circuitId The id of the circuit that its bucket should returned.
	 */
	public int bucketOf(int circuitId) {
		Preconditions.checkArgument(shuffledCircuits.contains(circuitId));
		return mapping.get(circuitId);
	}
	
	/**
	 * Returns the array represents this bucket.
	 * @param bucketIndex The id of the bucket that should be returned. 
	 */
	public int[] getBucket(int bucketIndex) {
		return buckets[bucketIndex];
	}
}
