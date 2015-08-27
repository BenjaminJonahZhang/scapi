#ifndef DLOG_MIRACL_H
#define DLOG_MIRACL_H

#include <random>
#include <iostream>
#include <zzn.h>
#include "DlogEllipticCurve.hpp"




Big biginteger_to_big(biginteger bi);
biginteger big_to_biginteger(Big b);

/**
* This class is an adapter for Fp points of miracl
*/
//forward decleration
class MiraclDlogECFp;

class ECFpPointMiracl : public virtual ECFpPoint {

	//private native long createFpPoint(long mip, byte[] x, byte[] y);
	//private native boolean checkInfinityFp(long point);
	//private native void deletePointFp(long p);
	//private native byte[] getXValueFpPoint(long mip, long point);
	//private native byte[] getYValueFpPoint(long mip, long point);

	//For performance reasons we decided to keep redundant information about the point. Once we have the member long point which is a pointer
	//to the actual point generated in the native code we do not really have a need to keep the BigIntegers x and y, since this data can be retrieved from the point.
	//However, to retrieve these values we need to perform an extra JNI call for each one plus we need to create a new BigInteger each time. It follows that each time
	//anywhere in the code the function ECFpPointMiracl::getX() gets called the following code would occur:
	//...
	//return new BigInteger(getXValueFpPoint(mip, point))
	//This seems to be very wasteful performance-wise, so we decided to keep the redundant data here. We think that it is not that terrible since this class is
	//immutable and once it is constructed there is not external way of re-setting the X and Y coordinates.
private:
	biginteger x;
	biginteger y;
	miracl* mip;
	epoint * point;

public:
	/**
	* Constructor that accepts x,y values of a point.
	* Miracl always checks validity of coordinates before creating the point.
	* If the values are valid - set the point, else throw IllegalArgumentException.
	* @param x the x coordinate of the candidate point
	* @param y the y coordinate of the candidate point
	* @param curve - DlogGroup
	* @throws IllegalArgumentException if the (x,y) coordinates do not represent a valid point on the curve
	*
	*/
	ECFpPointMiracl(biginteger x, biginteger y, MiraclDlogECFp * curve);

	/**
	* Constructor that gets pointer to element and sets it.
	* Only our inner functions use this constructor to set an element.
	* The ptr is a result of our DlogGroup functions, such as multiply.
	* @param ptr - pointer to native point
	*/
	ECFpPointMiracl(epoint * ptr, MiraclDlogECFp * curve);

	bool isIdentity() {
		return isInfinity();
	}

	bool isInfinity(){ return point_at_infinity(point);}

	/**
	* @return the pointer to the point
	*/
	epoint * getPoint() { return point; }

	biginteger getX() const override { return x; }

	biginteger getY() const override { return y; }

	GroupElementSendableData * generateSendableData() override {
		return new ECElementSendableData(getX(), getY());
	}

	int hashCode();
	bool ECFpPointMiracl::operator==(const GroupElement &other) const override;
	bool ECFpPointMiracl::operator!=(const GroupElement &other) const override;
	string toString() {
		return "ECFpPointMiracl [point= " + getX().str() + "; " + getY().str() + "]";
	}

	/**
	* delete the related point in Miracl's native code.
	*/
	virtual ~ECFpPointMiracl();
};

class MiraclAdapterDlogEC : public DlogGroupEC {
protected:
	//Class members:
	int window = 0;
	miracl * mip = NULL; ///MIRACL pointer
	// Map that holds a pointer to the precomputed values of exponentiating a given group element (the base) 
	//calculated in Miracl's native code
	std::unordered_map<GroupElement *, ebrick *> exponentiationsMap; //map for multExponentiationsWithSameBase calculations

	//temp member variable used for debug:
	//PrintWriter file;

	//Functions:
	MiraclAdapterDlogEC() {};
	virtual bool basicAndInfinityChecksForExpForPrecomputedValues(GroupElement * base)=0;
	virtual ebrick * initExponentiateWithPrecomputedValues(GroupElement * baseElement, biginteger exponent, int window, int maxBits)=0;
	virtual GroupElement * computeExponentiateWithPrecomputedValues(ebrick * ebrickPointer, biginteger exponent) = 0;
	
	//The window size is used when calling Miracl's implementation of exponentiate with pre-computed values. It is used as part of the Ebrick algorithm.
	int getWindow();

public:
	MiraclAdapterDlogEC(string fileName, string curveName, mt19937 prg = mt19937(clock())) : DlogGroupEC(fileName, curveName, prg){};

	/*
	* @return mip - miracl pointer
	*/
	miracl * getMip();
	void setWindow(int val) { window = val; }
	GroupElement * exponentiateWithPreComputedValues(GroupElement * base, biginteger exponent) override;
	
	/**
	* deletes the related Dlog group object
	*/
	~MiraclAdapterDlogEC();
};


/**
* This class implements an Elliptic curve Dlog group over Zp utilizing Miracl's implementation.<p>
* It uses JNI technology to call Miracl's native code.
*/
class MiraclDlogECFp : public MiraclAdapterDlogEC, public DlogECFp, public DDH {

private:
	ECFpUtility util;
	void createUnderlyingCurveAndGenerator(GroupParams * params);
	/*
	* return the w value that depends on the t bits
	*/
	int m_getLLW(int t);
	epoint* m_computeLL(const vector<epoint*> &points, const vector<big> &exponents, int n, int field);
	epoint ***m_createLLPreCompTable(const vector<epoint*> &points, int w, int h, int n, int field);
	epoint* m_getIdentity(int field);
	/*
	* computes the loop of the algorithm.
	* for k=0 to h-1
	*		e=0
	*		for i=kw to kw+w-1
	*			if the bitIndex bit in ci is set:
	*			calculate e += 2^(i-kw)
	*		result = result *preComp[k][e]
	*/
	epoint* m_computeLoop(const vector<big> &exponentiations, int w, int h, epoint *** preComp, epoint* result, int bitIndex, int n, int field);

protected:

	/**
	* Extracts the parameters of the curve from the properties object and initialize the groupParams,
	* generator and the underlying curve
	* @param curveName - the curve name as it called in the file
	*/
	void doInit(string curveName) override;
	bool basicAndInfinityChecksForExpForPrecomputedValues(GroupElement * base) override;
	/*
	* returns a pointer to newly created Ebrick structure in Miracl's native code.
	* @see edu.biu.scapi.primitives.dlog.miracl.MiraclAdapterDlogEC#initExponentiateWithPrecomputedValues(edu.biu.scapi.primitives.dlog.GroupElement, java.math.BigInteger, int, int)
	*/
	ebrick * initExponentiateWithPrecomputedValues(GroupElement * baseElement, biginteger exponent, int window, int maxBits) override;
	/*
	* actually compute the exponentiation in Miracl's native code using the previously created and computed Ebrick structure. The native function returns a pointer
	* to the computed result and this function converts it to the right GroupElement.
	* @see edu.biu.scapi.primitives.dlog.miracl.MiraclAdapterDlogEC#computeExponentiateWithPrecomputedValue(long, java.math.BigInteger)
	*/
	GroupElement * computeExponentiateWithPrecomputedValues(ebrick * ebrickPointer, biginteger exponent) override;

public:
	MiraclDlogECFp(string fileName = NISTEC_PROPERTIES_FILE, string curveName = "P - 192") : MiraclAdapterDlogEC(fileName, curveName) {
		doInit(curveName); // set the data and initialize the curve 
	};
	MiraclDlogECFp(string fileName, string curveName, mt19937 prg) : MiraclAdapterDlogEC(fileName, curveName, prg) {};
	
	/**
	* @return the type of the group - ECFp
	*/
	string getGroupType() override { return util.getGroupType(); };
	GroupElement * getInverse (GroupElement * groupElement) override;
	GroupElement * multiplyGroupElements(GroupElement * groupElement1, GroupElement * groupElement2) override;
	GroupElement * exponentiate(GroupElement * base, biginteger exponent) override;
	GroupElement * simultaneousMultipleExponentiations(vector<GroupElement *> groupElements, vector<biginteger> exponentiations) override;
	/**
	* This function generates a Group Element on this curve given the (x,y) values, if and only if the values are valid. Meaning that
	* this function always checks validity since the actual creation of the point is performed by Miracl's native code and
	* in the case of Miracle the validity of the (x, y) values is always checked. Therefore, even if this function is called
	* with bCheckMembership set to FALSE the validity check is performed.
	* @param bCheckMembership disregard this parameter, this function ALWAYS checks membership
	* @param values x and y coordinates of the requested point
	* @throws IllegalArgumentException if the number of elements of the values parameter is not 2 and/or
	* 								   if (x,y) do not represent a valid point on the curve
	* @see edu.biu.scapi.primitives.dlog.DlogGroup#generateElement(boolean, java.math.BigInteger[])
	*/
	GroupElement * generateElement(bool bCheckMembership, vector<biginteger> values) override;
	bool isMember(GroupElement * element) override;
	ECElement * getInfinity() override;
	virtual GroupElement * encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;	
	virtual const vector<unsigned char> decodeGroupElementToByteArray(GroupElement * groupElement) override;
	virtual const vector<unsigned char> mapAnyGroupElementToByteArray(GroupElement * groupElement) override;
	void endExponentiateWithPreComputedValues(GroupElement * base) override;


};



#endif