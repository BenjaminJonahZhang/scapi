package edu.biu.scapi.tests.dlog;


import java.io.IOException;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.bc.BcDlogECF2m;
import static org.junit.Assert.*;

public class TestBcDlogECF2m extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		try {
			return new BcDlogECF2m();
		} catch (IOException e) {
			fail("Got IOError");
			return null;
		}
	}
	
	public String getGroupType(){
		return "ECF2m";
	}
	
}

