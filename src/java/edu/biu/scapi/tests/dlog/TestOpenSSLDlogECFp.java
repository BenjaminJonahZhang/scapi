package edu.biu.scapi.tests.dlog;

import static org.junit.Assert.*;

import java.io.IOException;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.openSSL.OpenSSLDlogECFp;

public class TestOpenSSLDlogECFp extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		try {
			return new OpenSSLDlogECFp();
		} catch (IOException e) {
			fail("Got IOError");
			return null;
		}
	}
	
	public String getGroupType(){
		return "ECFp";
	}
}