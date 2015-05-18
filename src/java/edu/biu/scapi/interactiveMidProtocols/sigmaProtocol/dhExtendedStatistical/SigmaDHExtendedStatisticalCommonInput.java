/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2014 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dhExtendedStatistical;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDHExtendedStatistical verifier and simulator.<p>
 * In SigmaProtocolDHStatisticalExtended, the common input contains lists u, v such that y=log_u1 v1=log_u2 v2=...=log_un vn mod N
 * 
 * @author Eindhoven University of Technology (Meilof Veeningen)
 *
 */
public class SigmaDHExtendedStatisticalCommonInput implements SigmaCommonInput{

	private static final long serialVersionUID = 1908006771270405668L;
	
	private BigInteger N;
	
	private ArrayList<BigInteger> gArray;
	private ArrayList<BigInteger> hArray;
	
	/**
	 * Sets the input arrays.
	 * @param gArray
	 * @param hArray
	 */
	public SigmaDHExtendedStatisticalCommonInput(BigInteger N, ArrayList<BigInteger> gArray, ArrayList<BigInteger> hArray){
		this.N = N;
		this.gArray = gArray;
		this.hArray = hArray;
	}
	
	public BigInteger getN() {
		return N;
	}
	
	public ArrayList<BigInteger> getGArray(){
		return gArray;
	}
	
	public ArrayList<BigInteger> getHArray(){
		return hArray;
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
        int gSize = gArray.size();
		for(int i=0; i<gSize; i++){
			out.writeObject(gArray.get(i));
		}
		
		int hSize = hArray.size();
		for(int i=0; i<hSize; i++){
			out.writeObject(hArray.get(i));
		}
    }  
}
