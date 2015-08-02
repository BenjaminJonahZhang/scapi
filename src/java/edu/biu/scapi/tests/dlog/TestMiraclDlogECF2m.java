package edu.biu.scapi.tests.dlog;

import static org.junit.Assert.*;

import java.io.IOException;


import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;

public class TestMiraclDlogECF2m extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		try {
			return new MiraclDlogECF2m();
		} catch (IOException e) {
			fail("Got IOError");
			return null;
		}
	}
	
	public String getGroupType(){
		return "ECF2m";
	}
	
}