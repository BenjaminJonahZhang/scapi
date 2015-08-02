package edu.biu.scapi.tests.dlog;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.openSSL.OpenSSLDlogZpSafePrime;

public class TestOpenSSLDlogZpSafePrime extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		return new OpenSSLDlogZpSafePrime();
	}
	
	public String getGroupType(){
		return "Zp*";
	}
	
}
