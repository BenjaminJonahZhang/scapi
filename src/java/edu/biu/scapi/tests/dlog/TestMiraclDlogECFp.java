package edu.biu.scapi.tests.dlog;

import static org.junit.Assert.*;

import java.io.IOException;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECFp;

public class TestMiraclDlogECFp extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		try {
			return new MiraclDlogECFp();
		} catch (IOException e) {
			fail("Got IOError");
			return null;
		}
	}
	
	public String getGroupType(){
		return "ECFp";
	}
	
}