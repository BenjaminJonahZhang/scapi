package edu.biu.scapi.tests.dlog;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

public abstract class TestDlogGroupInterface {
	
	public abstract DlogGroup createInstance();
	public abstract String getGroupType();
	protected DlogGroup dlog = createInstance();
	

	@Test
	public void TestGetGroupType() {
	    assertEquals(getGroupType(), dlog.getGroupType());
	}
	
	@Test
	public void TestInvesreElement(){
		GroupElement ge = dlog.createRandomElement();
		GroupElement ige = dlog.getInverse(ge);
		GroupElement mul = dlog.multiplyGroupElements(ge, ige);
		GroupElement identity = dlog.getIdentity();
		
		for(GroupElement e: Arrays.asList(ge, ige, mul, identity))
			assertTrue(dlog.isMember(e));
		
		assertTrue(mul.isIdentity());
	}
	
	@Test
	public void TestExponentiate(){
		GroupElement ge = dlog.createRandomElement();
		GroupElement res_exp = dlog.exponentiate(ge, BigInteger.valueOf(3));
		GroupElement res_mul = dlog.multiplyGroupElements(dlog.multiplyGroupElements(ge, ge), ge);
		
		assertEquals(res_exp, res_mul);
	}
	
	@Test
	public void TestSimultaneousMultipleExponentiations(){
		GroupElement ge1 = dlog.createRandomElement();
		GroupElement ge2 = dlog.createRandomElement();
		BigInteger bi3 = BigInteger.valueOf(3);
		BigInteger bi4 = BigInteger.valueOf(4);
		
		GroupElement[] baseArray = {ge1, ge2};
		BigInteger[] exponentArray  = {bi3, bi4};
		
		GroupElement res1 = dlog.simultaneousMultipleExponentiations(baseArray, exponentArray);
		GroupElement expected_res = dlog.multiplyGroupElements(dlog.exponentiate(ge1, bi3), 
				dlog.exponentiate(ge2, bi4));
		
		assertEquals(res1, expected_res);
	}
	
	@Test
	public void TestExponentiateWithPreComputedValues(){
		GroupElement base = dlog.createRandomElement();
		
		BigInteger bi32 = BigInteger.valueOf(32);
		
		GroupElement res = dlog.exponentiateWithPreComputedValues(base, bi32);
		GroupElement expected_res = dlog.exponentiate(base, bi32);
		dlog.endExponentiateWithPreComputedValues(base);
		assertEquals(expected_res, res);
	}
	
	@Test
	public void TestEncodeDecode(){
		int k = dlog.getMaxLengthOfByteArrayForEncoding();
		if (k==0)
			return;

		byte[] bytes = new byte[k];
		new Random().nextBytes(bytes);
		GroupElement ge = dlog.encodeByteArrayToGroupElement(bytes);
		byte[] res_bytes = dlog.decodeGroupElementToByteArray(ge);
		assertEquals(new String(bytes), new String(res_bytes));
	}

}
