package edu.biu.scapi.tests.dlog;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.openSSL.OpenSSLDlogZpSafePrime;

public class TestOpenSSLDlogZpSafePrime extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		return new OpenSSLDlogZpSafePrime(64); // using 64bits to accelerate test
	}
	
	public String getGroupType(){
		return "Zp*";
	}
	
}
