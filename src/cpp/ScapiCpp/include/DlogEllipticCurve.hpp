#ifndef DLOG_EC_H
#define DLOG_EC_H

#include "Dlog.hpp"
#include <boost/algorithm/string.hpp>
#include <map>

typedef map<const string, string> CfgMap;

/**
* Marker interface. Every class that implements it, is signed as an elliptic curve point
*/
class ECElement : public virtual GroupElement {
public:
	/**
	* This function returns the x coordinate of the (x,y) point which is an element of a given elliptic curve.
	* In case of infinity point, returns null.
	* @return x coordinate of (x,y) point
	*/
	virtual biginteger getX() const = 0;
	/**
	* This function returns the y coordinate of the (x,y) point which is an element of a given elliptic curve.
	* In case of infinity point, returns null.
	* @return y coordinate of (x,y) point
	*/
	virtual biginteger getY() const = 0;
	/**
	* Elliptic curve has a unique point called infinity.
	* In order to know if this object is an infinity point, this function should be called.
	* @return true if this point is the infinity, false, otherwise.
	*/
	virtual bool isInfinity() = 0;
};

class ECElementSendableData : public GroupElementSendableData {
private:
	static const long serialVersionUID = 3494666921421090306L;

protected:
	biginteger x;
	biginteger y;

public:
	ECElementSendableData(biginteger x, biginteger y) {
		this->x = x;
		this->y = y;
	};
	biginteger getX() { return x; };
	biginteger getY() { return y; };
	string toString() { return "ECElementSendableData [x=" + x.str() + ", y=" + y.str() + "]"; };
	//virtual ~ECElementSendableData() {}; // must implement this to make the class concrete
};


/**
* Marker interface for elliptic curve point over the field Fp.
*/
class ECFpPoint : public virtual ECElement {};

/**
* This class holds the parameters of an elliptic curves Dlog group.
*/
class ECGroupParams : public GroupParams {
	// The class does not implement a concrete destructor. 
	// Hence remains abstract
private:
	static const long serialVersionUID = 7442260005331440764L;

protected:
	biginteger a; //coefficient a of the elliptic curve equation
	biginteger b; //coefficient b of the elliptic curve equation
	biginteger xG; //x coordinate of the generator point
	biginteger yG; //y coordinate of the generator point
	biginteger h;

public:

	/**
	* Returns coefficient a of the elliptic curves equation
	* @return coefficient a
	*/
	biginteger getA() { return a; };

	/**
	* Returns coefficient b of the elliptic curves equation
	* @return coefficient b
	*/
	biginteger getB() { return b; };

	/**
	* Returns the x coordinate of the generator point
	* @return the x value of the generator point
	*/
	biginteger getXg() { return xG; };

	/**
	* Returns the y coordinate of the generator point
	* @return the y value of the generator point
	*/
	biginteger getYg() { return yG; };

	/**
	* Returns the cofactor of the group
	* @return the cofactor of the group
	*/
	biginteger getCofactor() { return h; };
};

/**
* This class holds the parameters of an Elliptic curve over Zp.
*/
class ECFpGroupParams : public ECGroupParams {
private:
	static const long serialVersionUID = -5003549154325155956L;
	biginteger p; //modulus 

public:
	/**
	* Sets the order, generator and coefficients parameters
	* @param q group order
	* @param xG x coordinate of the generator point
	* @param yG y coordinate of the generator point
	* @param p group modulus
	* @param a the a coefficient of the elliptic curve equation
	* @param b the b coefficient of the elliptic curve equation
	* @param h the group cofactor
	*/
	ECFpGroupParams(biginteger q_, biginteger xG, biginteger yG, biginteger p, biginteger a, biginteger b, biginteger h) {
		this->q = q_;
		this->xG = xG;
		this->yG = yG;
		this->a = a;
		this->b = b;
		this->p = p;
		this->h = h;
	};

	/**
	* Returns the prime modulus of the group
	* @return p
	*/
	biginteger getP() { return p; };

	string toString() {
		return "ECFpGroupParams [p=" + p.str() + ", /na=" + a.str() + ", /nb=" + b.str() +
			", /nxG=" + xG.str() + ", /nyG=" + yG.str() + ", /nh=" + h.str() + ", /nq=" + q.str() + "]";
	}
	
	// implementing a destructor to make it concrete class
	//~ECFpGroupParams() override {};
};








/**
* Marker interface. Every class that implements it is signed as elliptic curve.
*/
class DlogEllipticCurve : public virtual DlogGroup {
public:
	/**
	* @return the infinity point of this dlog group
	*/
	virtual ECElement * getInfinity() = 0;

	/**
	* @return the name of the curve. For example - P-192.
	*/
	virtual string getCurveName() = 0;
	/**
	* @return the properties file where the curves are defined.
	*/
	virtual string getFileName() = 0;
};

/**
* Marker interface. Every class that implements it is signed as elliptic curve over F[p]
*/
class DlogECFp : public virtual DlogEllipticCurve {};
/**
* This class manages the creation of NIST recommended elliptic curves.
* We have a properties file which contains the parameters for the curves.
* This class uploads the file once, and constructs a properties object from it.
*/
class DlogGroupEC : public virtual DlogGroupAbs, public virtual DlogEllipticCurve {
private:
	CfgMap nistProperties; // properties object to hold nist parameters
protected:
	static const string NISTEC_PROPERTIES_FILE;
	string curveName;
	string fileName;
	DlogGroupEC() {};

	/**
	* Constructor that initializes this DlogGroup with a curve that is not necessarily one of NIST recommended elliptic curves.
	* @param fileName - name of the elliptic curves file. This file has to comply with
	* @param curveName - name of curve to initialized
	* @throws IOException
	*/
	DlogGroupEC(string fileName, string curveName, mt19937 prg = mt19937(clock()));
	virtual void doInit(string curveName) = 0;

	CfgMap getProperties(string fileName);

public:
	string getCurveName() { return curveName; };
	string getFileName() { return fileName; };
	/**
	* Checks parameters of this group to see if they conform to the type this group is supposed to be.<p>
	* Parameters are uploaded from a configuration file upon construction of concrete instance of an Elliptic Curve Dlog group.
	* By default, SCAPI uploads a file with NIST recommended curves. In this case we assume the parameters are always correct.
	* It is also possible to upload a user-defined configuration file (with format specified in the "Elliptic Curves Parameters File Format" section of the FirstLevelSDK_SDD.docx file). In this case,
	* it is the user's responsibility to check the validity of the parameters.
	* In both ways, the parameters we set should be correct. Therefore, currently the function validateGroup does not perform any validity check and always returns true.
	* In the future we may add the validity checks.
	* @return true.
	*/
	virtual bool validateGroup() override { return true; };
	/**
	* Checks if the element set as the generator is indeed the generator of this group.
	* The generator is set upon construction of this group. <p>
	* For Elliptic curves there are two ways to set the generator. One way is to load it from NIST file, so the generator is correct.
	* The second way is to get the generator values from the user in the init function. In that way, it is the user's responsibility to check the validity of the parameters.
	* In both ways, the generator we set must be correct. However, currently the function isGenerator does not operate the validity check and always returns true.
	* Maybe in the future we will add the validity checks.
	* @return <code>true</code> is the generator is valid;<p>
	* 		   <code>false</code> otherwise.
	*
	*/
	virtual bool isGenerator() override { return true; };

	/**
	* For Elliptic Curves, the identity is equivalent to the infinity.
	* @return the identity of this Dlog group
	*/
	virtual GroupElement * getIdentity() override { return getInfinity(); };

	virtual GroupElement * reconstructElement(bool bCheckMembership, GroupElementSendableData * data) override;
};

/**
* This class is a utility class for elliptic curve classes over Fp field.
* It operates some functionality that is common for every elliptic curve over Fp.
*/
class ECFpUtility {
public:
	/**
	* Checks if the given x and y represent a valid point on the given curve,
	* i.e. if the point (x, y) is a solution of the curves equation.
	* @param params elliptic curve over Fp parameters
	* @param x coefficient of the point
	* @param y coefficient of the point
	* @return true if the given x and y represented a valid point on the given curve
	*/
	bool checkCurveMembership(ECFpGroupParams * params, biginteger x, biginteger y);

	/**
	* This function finds the y coordinate of a point in the curve for a given x, if it exists.
	* @param params the parameters of the group
	* @param x
	* @return the y coordinate of point in the curve for a given x, if it exists
	* 			else, null
	*/
	biginteger findYInCurveEquationForX(ECFpGroupParams params, biginteger x);

	// Auxiliary class used to hold the (x,y) coordinates of a point.
	// It does not have any information about the curve and any further checks regarding membership
	// to any specific curve should be performed by the user of this auxiliary class.
	class FpPoint {
	protected:
		biginteger x;
		biginteger y;
	public:
		FpPoint(biginteger x, biginteger y) {
			this->x = x;
			this->y = y;
		};
		biginteger getX() { return x; };
		biginteger getY() { return y; };
	};

	/**
	* This function receives any string of size up to k bytes (as returned by CalcK), finds the coordinates of the point that is the encoding of this binary string.
	* @param binaryString
	* @throws IndexOutOfBoundsException if the length of the binary array to encode is longer than k
	* @return an FpPoint with the coordinates of the corresponding GroupElement point or null if could not find the encoding in reasonable time
	*/
	FpPoint * findPointRepresentedByByteArray(ECFpGroupParams params, const vector<byte> & binaryString, int k);

	/**
	* checks if the given point is in the given dlog group with the q prime order.
	* A point is in the group if it in the q-order group which is a sub-group of the Elliptic Curve.
	* Base assumption of this function is that checkCurveMembership function is already been called and returned true.
	* @param curve
	* @param point
	* @return true if the given point is in the given dlog group.
	*/
	bool checkSubGroupMembership(DlogECFp * curve, ECFpPoint * point);

	/**
	* This function maps any group element to a byte array. This function does not have an inverse,<p>
	* that is, it is not possible to re-construct the original group element from the resulting byte array.
	* @param x coordinate of a point in the curve (this function does not check for membership)
	* @param y coordinate of a point in the curve (this function does not check for membership)
	* @return byte[] representation
	*/
	vector<unsigned char> mapAnyGroupElementToByteArray(biginteger x, biginteger y);

	/**
	* This function calculates k, the maximum length in bytes of a string to be converted to a Group Element of this group.
	* @param p
	* @return k
	*/
	int calcK(biginteger p);

	/**
	* This function returns the k least significant bytes of the number x
	* @param x
	* @param k
	* @return k least significant bits of x
	*/
	vector<unsigned char> getKLeastSignBytes(biginteger x, int k);

	/**
	* This function receives the name of a curve and some possible properties and it checks that curve is actually a curve over the Fp field. If so, it creates the necessary
	* GroupParams. Else, throws  IllegalArgumentException.
	* @param ecProperties
	* @param curveName
	* @return the GroupParams if this curve is a curve over the Fp field.
	* @throws IllegalArgumentException if curveName is not a curve over Fp field and doesn't match the DlogGroup type.
	*/
	GroupParams * checkAndCreateInitParams(CfgMap ecProperties, string curveName);

	/**
	* @return the type of the group - ECFp
	*/
	string getGroupType() { return "ECFp"; };
};

#endif