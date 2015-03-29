package edu.biu.protocols.yao.primitives;

/**
 * This class creates the K probe resistant matrix.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class KProbeResistantMatrixBuilder {
	
	// Known dimensions.
	//For more information and details about them, see "Blazing Fast 2PC in the "Offline/Online Setting with Security 
	//for Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, Appendix D.
	private final int n;			//Rows number of the matrix.
	private final int k;			//Security parameter.
	private int m;
	private int t;
	private int K;
	private int N;
	
	/**
	 * Native function that builds the matrix.
	 * @return the created matrix.
	 */
	private native byte[][] createMatrix(int n, int t, int K, int N);
	
	/**
	 * Constructor that sets the given arguments and calculates the matrix dimensions.
	 * @param n Rows number of the matrix.
	 * @param k Security parameter.
	 */
	public KProbeResistantMatrixBuilder(int n, int k) {
		this.n = n;
		this.k = k;
		calculateDimensions();
	}
	
	/**
	 * Builds the probe resistant matrix using native call.
	 * @return the created matrix.
	 */
	public KProbeResistantMatrix build() {
		//Call the native function to create the matrix.
		byte[][] matrix = createMatrix(n, t, K, N);
		
		//Create an extended matrix and copy each row of the native matrix to the new one. 
		byte[][] extendedMatrix = new byte[n][m + n];
		for (int i = 0; i < matrix.length; i++) {
			System.arraycopy(matrix[i], 0, extendedMatrix[i], 0, m);
		}
		
		// Copy a diagonal matrix (I) on the right side of the probe resistant matrix,
		// in order to allow opportunistic allocation of shares.
		for (int i = 0; i < extendedMatrix.length; i++) {
			for (int j = 0; j < n; j++) {
				if (j == i) {
					extendedMatrix[i][m + j] = 1; 
				} else {
					extendedMatrix[i][m + j] = 0;
				}
			}
		}
		// Return (M | I)
		return new KProbeResistantMatrix(extendedMatrix);
	}
	
	/**
	 * Calculates the matrix dimensions, see "Offline/Online Setting with Security /for Malicious Adversaries" 
	 * paper by Yehuda Lindell and Ben Riva, Appendix D.
	 */
	private void calculateDimensions() {
		t = (int) Math.ceil(Math.max(log2(n<<2), log2(k<<2)));
		
		while (tIsToLarge()) {
			t = t - 1;
		}
		
		K = (int) Math.ceil((log2(n) + n + k) / (double)t);
		N = K + k - 1;
		m = N * t;
	}
	
	/**
	 * Returns true if the value of t is too large for the computation.
	 */
	private boolean tIsToLarge() {
		double a = (double) (1 << (t - 1));
		double b = k + ((log2(n) + n + k) / (t - 1));
		return (a > b);
	}

	/**
	 * Computes log(x) on base 2.
	 * @return the result of the log operation.
	 */
	private double log2(int x) {
		return Math.log10(x) / Math.log10(2);
	}
	
	static {	 
		 //load the NTL jni dll
		 System.loadLibrary("NTLJavaInterface");
	}
}
