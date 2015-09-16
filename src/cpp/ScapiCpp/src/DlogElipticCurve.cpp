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

bool ECFpUtility::checkSubGroupMembership(DlogECFp * curve, ECFpPoint * point)
{
	// we assume that the point is on the curve group
	// get the cofactor of the group
	ECFpGroupParams * params = (ECFpGroupParams *) curve->getGroupParams();
	biginteger h = params->getCofactor();

	//if the cofactor is 1 the sub-group is same as the elliptic curve equation which the point is in.
	if (h==1)
		return true;

	biginteger y = point->getY();

	// if the cofactor is greater than 1, the point must have order q (same as the order of the group)

	// if the cofactor is 2 and the y coefficient is 0, the point has order 2 and is not in the group
	if (h==2)
		return (y != 0);

	// if the cofactor is 3 and p^2 = p^(-1), the point has order 3 and is not in the group
	if (h==3) {
		GroupElement * power = curve->exponentiate(point, 2);
		GroupElement * inverse = curve->getInverse(point);
		return (power != inverse);
	}

	// if the cofactor is 4, the point has order 2 if the y coefficient of the point is 0, 
	// or the the point has order 4 if the y coefficient of the point raised to two is 0.
	// in both cases the point is not in the group.
	if (h==4) {
		if (y==0) {
			return false;
		}
		GroupElement * power = curve->exponentiate(point, 2);
		biginteger powerY = dynamic_cast<ECElement *>(power)->getY();
		return (y != 0);
	}

	// if the cofactor is bigger than 4, there is no optimized way to check the order, so we operates the naive:
	// if the point raised to q (order of the group) is the identity, the point has order q too and is in the group. 
	// else, it is not in the group
	biginteger r = params->getQ();
	GroupElement * pointPowR = curve->exponentiate(point, r);
	return point->isIdentity();
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
	int bitsInp = NumberOfBits(p);
	int k = (int)floor((0.4 * bitsInp) / 8) - 1;
	//For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
	//the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
	if (k > 255) {
		k = 255;
	}
	return k;
}

ECFpUtility::FpPoint * ECFpUtility::findPointRepresentedByByteArray(ECFpGroupParams params, const vector<byte> & binaryString, int k)
{
	//Pseudo-code:
	/*If the length of binaryString exceeds k then throw IndexOutOfBoundsException.

	Let L be the length in bytes of p

	Choose a random byte array r of length L - k - 2 bytes

	Prepare a string newString of the following form: r || binaryString || binaryString.length (where || denotes concatenation) (i.e., the least significant byte of newString is the length of binaryString in bytes)

	Convert the result to a BigInteger (bIString)

	Compute the elliptic curve equation for this x and see if there exists a y such that (x,y) satisfies the equation.

	If yes, return (x,y)

	Else, go back to step 3 (choose a random r etc.) up to 80 times (This is an arbitrary hard-coded number).

	If did not find y such that (x,y) satisfies the equation after 80 trials then return null.
	*/


	if (binaryString.size() > k)
		throw out_of_range("The binary array to encode is too long.");
	
	int l = NumberOfBits(params.getP()) / 8;
	int randomArraySize = 1 - k - 2;
	vector<byte> randomVector;
	randomVector.reserve(randomArraySize);

	int len_newString = randomArraySize + 1 + binaryString.size();
	byte * newString = new byte[len_newString];
	int counter = 0;
	biginteger y = NULL;
	biginteger x = NULL;
	do {
		gen_random_bytes_vector(randomVector, randomArraySize);
		copy_byte_vector_to_byte_array(randomVector, newString, 0);
		copy_byte_vector_to_byte_array(binaryString, newString, randomArraySize);
		newString[len_newString - 1] = (byte)binaryString.size();
		
		// Convert the result to a BigInteger (bIString)
		x = decodeBigInteger(newString, len_newString);
		if (x<0) {
			byte * temp = new byte[len_newString];
			encodeBigInteger(x, temp, len_newString);
			byte t0 = temp[0];
			temp[0] = (byte)-t0;
			x = decodeBigInteger(temp, len_newString);
			delete temp;
		}

		// Compute the elliptic curve equation for this x and see if there exists a y such that (x,y) satisfies the equation.
		// If yes, return (x,y)
		// Else, go back to choose a random r etc.)
		y = findYInCurveEquationForX(params, x);
		counter++;

	} while ((y == NULL) && (counter <= 80)); //we limit the amount of times we try to 80 which is an arbitrary number.

	delete newString;
	// If found the correct y in reasonable time then return the (x,y) FpPoint
	if (y != NULL)
		return new FpPoint(x, y);
	//Otherwise, return null
	return NULL;
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