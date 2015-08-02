package edu.biu.scapi.tests.dlog;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;

public class TestCryptoPpDlogZpSafePrime extends TestDlogGroupInterface{

	public DlogGroup createInstance(){
		return new CryptoPpDlogZpSafePrime();
	}
	
	public String getGroupType(){
		return "Zp*";
	}
	
}

