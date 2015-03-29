package edu.biu.protocols.yao.common;

/**
 * This class provides a tool to measure times.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class LogTimer {
	private long start;				// Used to hold the start time of some action.
	private long end;				// Used to hold the end time of some action.
	private String name;			// Holds the name of the measured action. 
	private final boolean verbose;	//Indicates whether or not print the times.
	
	/**
	 * Starts the timer. The times will be printed.
	 * @param name The name of the started action.
	 */
	public LogTimer(String name) {
		this(name, true);
	}
	
	/**
	 * Starts the timer. 
	 * @param name The name of the started action.
	 * @param verbose Indicates whether or not print the times.
	 */
	public LogTimer(String name, boolean verbose) {
		this.reset(name);
		this.verbose = verbose;
	}

	/**
	 * Restarts the timer.
	 * @param name  The name of the restarted action.
	 */
	public void reset(String name) {
		this.name = name;
		this.start = System.nanoTime();
		if (verbose) {
			System.out.println("started " + name + "...");
		}
	}

	/**
	 * Stops the timer.
	 */
	public void stop() {
		end = System.nanoTime();
		long runtime = (end - start);
		if (verbose) {
			System.out.println(name + " took " + runtime + " miliseconds.");
			System.out.println("--------------------------------------------------------------------------------");
		}
	}
}
