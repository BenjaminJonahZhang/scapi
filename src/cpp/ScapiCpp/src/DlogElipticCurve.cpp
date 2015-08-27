#include "../include/DlogEllipticCurve.hpp"

string convert_hex_to_string(string hex)
{
	return hex;
}
/*******************************************/
/******** ECFpUtility Implementation ******/
/******************************************/

bool ECFpUtility::checkCurveMembership(ECFpGroupParams * params, biginteger x, biginteger y) {
 	 /* get a, b, p from group params */
	 biginteger a = params->getA();
	 biginteger b = params->getB();
	 biginteger p = params->getP();

	 //Calculates the curve equation with the given x,y.

	 // compute x^3 % p
	 biginteger x3 = mp::powm(x, 3, p);
	 // compute x^3+ax+b
	 biginteger rightSide = (x3 + (a*x) + b) % p;
	 // compute y^2
	 biginteger leftSide = mp::powm(y, 2, p);

	 // if the the equation is solved - the point is in the elliptic curve and return true
	 if (leftSide == rightSide)
		 return true;
	 else return false;
}

biginteger ECFpUtility::findYInCurveEquationForX(ECFpGroupParams params, biginteger x) {

	/* get a, b, p from group params */
	biginteger a = params.getA();
	biginteger b = params.getB();
	biginteger p = params.getP();


	// compute x^3
	biginteger x3 = mp::powm(x, 3, p);
	// compute x^3+ax+b
	biginteger rightSide = (x3 + (a*x) + b) % p;

	//try to compute y = square_root(x^3+ax+b)
	//If it exists return it
	//else, return null
	biginteger remider;
	auto y = mp::sqrt(rightSide, remider);

	if (remider == 0)
		return y % p;
	else 
		return NULL;
}

GroupParams * ECFpUtility::checkAndCreateInitParams(CfgMap ecProperties, string curveName) {
	// check that the given curve is in the field that matches the group
	if (!boost::algorithm::starts_with(curveName, "P-")) //	if (!curveName.startsWith("P-")) {
		throw invalid_argument("curveName is not a curve over Fp field and doesn't match the DlogGroup type");

	// get the curve parameters
	biginteger p(ecProperties[curveName]);
	biginteger a(ecProperties[curveName + "a"]);
	biginteger b(convert_hex_to_string(ecProperties[curveName + "b"]));   // make sure it is possitve?
	biginteger x(convert_hex_to_string(ecProperties[curveName + "x"]));  // make sure it is possitve?
	biginteger y(convert_hex_to_string(ecProperties[curveName + "y"]));   // make sure it is possitve?
	biginteger q(ecProperties[curveName + "r"]);
	biginteger h(ecProperties[curveName + "h"]);

	// create the GroupParams
	GroupParams * groupParams = new ECFpGroupParams(q, x, y, p, a, b, h);
	return groupParams;
}

int ECFpUtility::calcK(biginteger p) {
	int bitsInp = bitlength(p);
	int k = (int)floor((0.4 * bitsInp) / 8) - 1;
	//For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
	//the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
	if (k > 255) {
		k = 255;
	}
	return k;
}

/*******************************************/
/******** DlogGroupEC Implementation ******/
/******************************************/

const string DlogGroupEC::NISTEC_PROPERTIES_FILE = "/propertiesFiles/NISTEC.properties";

DlogGroupEC::DlogGroupEC(string fileName, string curveName, mt19937 prg){
	this->curveName = curveName;
	this->fileName = fileName;
	this->random_element_gen = prg;
}

CfgMap DlogGroupEC::getProperties(string fileName){
	//If we had already open the NISTEC file then do not open it again, just return it.
	if (fileName == NISTEC_PROPERTIES_FILE && nistProperties.size() > 0)
		return nistProperties;

	CfgMap ecProperties;

	//Load the elliptic curves file
	//Instead of loading the plain file, which only works from outside a jar file, we load it as a resource 
	//that can also work from within a jar file. The path from which we load the properties file from is from now under bin\propertiesFiles.
	//InputStream in = (InputStream)getClass().getResourceAsStream(fileName);
	//ecProperties.load(in);

	//Set the member variable nistProperties to the recently loaded ecProperties file, so that next time
	//the NIST file has to be read, the already loaded file will be returned. (See above). 
	if (fileName == NISTEC_PROPERTIES_FILE)
		nistProperties = ecProperties;

	return ecProperties;
}

GroupElement * DlogGroupEC::reconstructElement(bool bCheckMembership, GroupElementSendableData * data) {
	ECElementSendableData * ec_element = dynamic_cast<ECElementSendableData *>(data);
	if(!ec_element)
		throw invalid_argument("data type doesn't match the group type");
	vector<biginteger> values = { ec_element->getX(), ec_element->getY() };
	return generateElement(bCheckMembership, values);
}