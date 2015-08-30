#include "../include/DlogEllipticCurve.hpp";

/*******************************************/
/******** ECFpUtility Implementation ******/
/******************************************/

bool ECFpUtility::checkCurveMembership(ECFpGroupParams params, biginteger x, biginteger y) {
 	 /* get a, b, p from group params */
	 biginteger a = params.getA();
	 biginteger b = params.getB();
	 biginteger p = params.getP();

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


/*******************************************/
/******** DlogGroupEC Implementation ******/
/******************************************/

const string DlogGroupEC::NISTEC_PROPERTIES_FILE = "/propertiesFiles/NISTEC.properties";

DlogGroupEC::DlogGroupEC(string fileName, string curveName, mt19937 prg = mt19937(clock())){
	CfgMap ecProperties;
	ecProperties = getProperties(fileName); //get properties object containing the curve data
	
	//checks that the curveName is in the file 
	if(ecProperties.find(curveName)==ecProperties.end()) // not found
		throw invalid_argument("no such elliptic curve in the given file");

	this->curveName = curveName;
	this->fileName = fileName;
	this->random_element_gen = prg;
	doInit(ecProperties, curveName); // set the data and initialize the curve
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


GroupElement * MiraclAdapterDlogEC::exponentiateWithPreComputedValues(GroupElement * base, biginteger exponent) {
	
	//This function performs basic checks on the group element, such as if it is of the right type for the relevant Dlog and checks if the 
	//base group element is the infinity. If so, then the result of exponentiating is the base group element itself, return it.
	bool infinity = basicAndInfinityChecksForExpForPrecomputedValues(base);
	if (infinity)
		return base;

	//Look for the base in the map. If this is the first time we calculate the exponentiations for this base then:
	//1) we will not find the base in the map
	//2) we need to perform the pre-computation for this base
	//3) and then save the pre-computation for this base in the map
	auto pos = exponentiationsMap.find(base);
	long ebrickPointer;
	//If didn't find the pointer for the base element, create one:
	if (pos==exponentiationsMap.end()) {
		//the actual pre-computation is performed by Miracl. The call to this function returns a pointer to an "ebrick"
		//structure created and held by the Miracl code. We save this pointer in the map for the current base and pass it on
		//to the actual computation of the exponentiation in the step below.
		ebrickPointer = initExponentiateWithPrecomputedValues(base, exponent, getWindow(), getOrder().bitLength());
		exponentiationsMap[base] =  ebrickPointer;
	}
	//At this stage we have a pointer to the ebrick pointer in native code, and we pass it on to compute base^exponent and obtain the resulting Group Element
	Long ebrickPointer = exponentiationsMap.get(base);
	return computeExponentiateWithPrecomputedValues(ebrickPointer, exponent);

}