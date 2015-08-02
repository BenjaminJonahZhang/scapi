package edu.biu.scapi.tests.dlog;

import static org.junit.Assert.*;

import java.io.IOException;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.bc.BcDlogECFp;

public class TestBcDlogECFp  extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		try {
			return new BcDlogECFp();
		} catch (IOException e) {
			fail("Got IOError");
			return null;
		}
	}
	
	public String getGroupType(){
		return "ECFp";
	}
	
}

