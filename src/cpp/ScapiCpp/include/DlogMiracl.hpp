#ifndef DLOG_MIRACL_H
#define DLOG_MIRACL_H

#include <random>
#include <big.h>
extern "C" {
#include <miracl.h>
}
#include "DlogEllipticCurve.hpp"

class MiraclAdapterDlogEC : public DlogGroupEC, public DlogEllipticCurve {
protected:
	//Class members:
	int window = 0;
	miracl * mip = NULL; ///MIRACL pointer
	// Map that holds a pointer to the precomputed values of exponentiating a given group element (the base) 
	//calculated in Miracl's native code
	std::unordered_map<GroupElement *, long *> exponentiationsMap; //map for multExponentiationsWithSameBase calculations

	//temp member variable used for debug:
	//PrintWriter file;

	//Functions:
	MiraclAdapterDlogEC() {};
	virtual bool basicAndInfinityChecksForExpForPrecomputedValues(GroupElement * base)=0;
	virtual long initExponentiateWithPrecomputedValues(GroupElement * baseElement, biginteger exponent, int window, int maxBits)=0;
	virtual GroupElement * computeExponentiateWithPrecomputedValues(long ebrickPointer, biginteger exponent) = 0;
	
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

protected:
	/**
	* Extracts the parameters of the curve from the properties object and initialize the groupParams,
	* generator and the underlying curve
	* @param ecProperties - properties object contains the curve file data
	* @param curveName - the curve name as it called in the file
	*/
	void doInit(CfgMap ecProperties, string curveName) override;
	bool basicAndInfinityChecksForExpForPrecomputedValues(GroupElement * base) override;
	/*
	* returns a pointer to newly created Ebrick structure in Miracl's native code.
	* @see edu.biu.scapi.primitives.dlog.miracl.MiraclAdapterDlogEC#initExponentiateWithPrecomputedValues(edu.biu.scapi.primitives.dlog.GroupElement, java.math.BigInteger, int, int)
	*/
	long initExponentiateWithPrecomputedValues(GroupElement * baseElement, biginteger exponent, int window, int maxBits) override;
	/*
	* actually compute the exponentiation in Miracl's native code using the previously created and computed Ebrick structure. The native function returns a pointer
	* to the computed result and this function converts it to the right GroupElement.
	* @see edu.biu.scapi.primitives.dlog.miracl.MiraclAdapterDlogEC#computeExponentiateWithPrecomputedValue(long, java.math.BigInteger)
	*/
	GroupElement * computeExponentiateWithPrecomputedValues(long ebrickPointer, biginteger exponent) override;

public:
	MiraclDlogECFp(string fileName = NISTEC_PROPERTIES_FILE, string curveName = "P - 192") : MiraclAdapterDlogEC(fileName, curveName) {};
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