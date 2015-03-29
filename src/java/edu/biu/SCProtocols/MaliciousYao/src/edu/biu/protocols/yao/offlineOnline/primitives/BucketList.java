package edu.biu.protocols.yao.offlineOnline.primitives;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.ArrayList;

import edu.biu.protocols.yao.common.Preconditions;

/**
 * This class is an array that holds arrays of Bundles or LimitedBundles. Each inner array is called "bucket".<p>
 * 
 * It provides some functionality as any array (add, size, get) as well as special functionalities 
 * regarding bundles (saveToFiles, loadToFiles).
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 * @param <T>
 */
public class BucketList<T>  {
	
	private final int numBuckets;				// The number of buckets (arrays)) in the list.
	private final int bucketSize;				// The number of bundles in each bucket.
	private final BucketMapping bucketMapping;	// An object that maps a bundle into the right bucket.
	private ArrayList<ArrayList<T>> items;		// Arrays that stores all bundles.
	
	/**
	 * A constructor that initializes the list using the given execution parameters and bucketMapping.
	 * @param execution contains the number of buckets and bucket size.
	 * @param bucketMapping An object that maps a bundle into the right bucket.
	 */
	public BucketList(ExecutionParameters execution, BucketMapping bucketMapping) {
		this.numBuckets = execution.numberOfExecutions();
		this.bucketSize = execution.bucketSize();
		this.bucketMapping = bucketMapping;
		
		//Create the arrays of the buckets.
		this.items = new ArrayList<ArrayList<T>>();
		for (int i = 0; i < numBuckets; i++) {
			items.add(new ArrayList<T>());
		}
	}
	
	/**
	 * Adds the given item to the list.
	 * @param item To add to the list.
	 * @param index The index that the item should be placed at.
	 */
	public void add(T item, int index) {
		//Get the id of the bucket where the item should be placed.
		int bucketId = bucketMapping.bucketOf(index);
		
		//Put the item in the right bucket.
		items.get(bucketId).add(item);
	}
	
	/**
	 * Returns the number of buckets in the list.
	 */
	public int size() {
		return numBuckets;
	}
	
	/**
	 * Returns the bucket according to the given id.
	 * @param bucketId The id of the requested bucket.
	 */
	public ArrayList<T> getBucket(int bucketId) {
		Preconditions.checkIndexInRange(bucketId, numBuckets);
		return items.get(bucketId);
	}
	
	/**
	 * Returns the bundle according to the given item and bucket ids.
	 * @param bucketId The id of the bucket where the item is placed.
	 * @param itemId The id of the requested item.
	 */
	public T getBundle(int bucketId, int itemId) {
		Preconditions.checkIndexInRange(bucketId, numBuckets);
		Preconditions.checkIndexInRange(itemId, bucketSize);
		return items.get(bucketId).get(itemId);
	}
	
	/**
	 * Prints the buckets to files. Each bucket is printed to a different file.
	 * @param prefix The prefix of the files names.
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public void saveToFiles(String prefix) throws FileNotFoundException, IOException {
		//For each bucket, create a file and write the bucket.
		for (int j = 0; j < numBuckets; j++) {
			//The name of the file is the given prefix along with the number of the bucket.
			String filename = String.format("%s.%d.cbundle", prefix, j);
			ObjectOutput output = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
			//Write the entire array of items to the file and close it.
			output.writeObject(items.get(j));
			output.close();
		}
	}
	
	/**
	 * Loads a bucket of Bundles from a file. (This actually reads one bucket in each function call).
	 * @param filename The name of the file to read from.
	 * @return The created array filled with items. 
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public static ArrayList<Bundle> loadBucketFromFile(String filename) throws FileNotFoundException, IOException, ClassNotFoundException {
		//Open the file.
		ObjectInput input = new ObjectInputStream(new BufferedInputStream(new FileInputStream(filename)));
		@SuppressWarnings("unchecked")
		//Read the bucket and return it.
		ArrayList<Bundle> bucket = (ArrayList<Bundle>) input.readObject();
		input.close();
		return bucket;
	}
	
	/**
	 * Loads a bucket of LimitedBundles from a file. (This actually reads one bucket in each function call).
	 * @param filename The name of the file to read from.
	 * @return The created array filled with items. 
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public static ArrayList<LimitedBundle> loadLimitedBucketFromFile(String filename) throws FileNotFoundException, IOException, ClassNotFoundException {
		//Open the file.
		ObjectInput input = new ObjectInputStream(new BufferedInputStream(new FileInputStream(filename)));
		@SuppressWarnings("unchecked")
		//Read the bucket and return it.
		ArrayList<LimitedBundle> bucket = (ArrayList<LimitedBundle>) input.readObject();
		input.close();
		return bucket;
	}
}
