#include "../include/DlogMiracl.hpp"

Miracl precision(500, 10); // this makes sure that miracl
						   // is initialised before main()	// is called

Big biginteger_to_big(biginteger bi)
{
	char * s = new char[bi.str().length() + 1];
	strcpy(s, bi.str().c_str());
	return Big(s);
}

biginteger big_to_biginteger(Big b) {
	string s = boost::lexical_cast<std::string>(b);
	return biginteger(s);
}

/****************************************************/
/******** MiraclAdapterDlogEC Implementation ******/
/***************************************************/

miracl * MiraclAdapterDlogEC::getMip() {
	if (!mip)
		mip = mirsys(400, 16); 
	return mip;
}

MiraclAdapterDlogEC::~MiraclAdapterDlogEC()
{
	mirexit();
}

GroupElement * MiraclAdapterDlogEC::exponentiateWithPreComputedValues(GroupElement * base, biginteger exponent) {
	//This function performs basic checks on the group element, such as if it is of the right type for the relevant Dlog and checks if the 
	//base group element is the infinity. If so, then the result of exponentiating is the base group element itself, return it.
	bool infinity = basicAndInfinityChecksForExpForPrecomputedValues(base);
	if (infinity)
		return base;
	
	// Look for the base in the map. If this is the first time we calculate the exponentiations for this base then:
	// 1) we will not find the base in the map
	// 2) we need to perform the pre-computation for this base
	// 3) and then save the pre-computation for this base in the map
	ebrick * ebrickPointer;
	auto p = exponentiationsMap.find(base);
	//If didn't find the pointer for the base element, create one:
	if (p == exponentiationsMap.end()) {
		//the actual pre-computation is performed by Miracl. The call to this function returns a pointer to an "ebrick"
		//structure created and held by the Miracl code. We save this pointer in the map for the current base and pass it on
		//to the actual computation of the exponentiation in the step below.
		ebrickPointer = initExponentiateWithPrecomputedValues(base, exponent, getWindow(), NumberOfBits(getOrder()));
		exponentiationsMap[base] = ebrickPointer;
	}
	else
		ebrickPointer = p->second;
	//At this stage we have a pointer to the ebrick pointer in native code, and we pass it on to compute base^exponent and obtain the resulting Group Element
	return computeExponentiateWithPrecomputedValues(ebrickPointer, exponent);
}

int MiraclAdapterDlogEC::getWindow() {
	if (window != 0) {
		return window;
	}
	int bits = NumberOfBits(getOrder());
	if (bits <= 256) {
		window = 8;
	}
	else {
		window = 10;
	}
	return window;
}

/****************************************************/
/******** MiraclDlogECFp Implementation ******/
/***************************************************/

void MiraclDlogECFp::doInit(string curveName) {
	CfgMap ecProperties;
	ecProperties = getProperties(fileName); //get properties object containing the curve data
	
	// checks that the curveName is in the file 
	if (ecProperties.find(curveName) == ecProperties.end()) // not found
		throw invalid_argument("no such elliptic curve in the given file");

	ECFpUtility util;
	this->groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
	//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
	biginteger p = ((ECFpGroupParams *)groupParams)->getP();
	k = util.calcK(p);
	createUnderlyingCurveAndGenerator(groupParams);
}

void MiraclDlogECFp::createUnderlyingCurveAndGenerator(GroupParams * params) {
	//There is no need to check that the params passed are an instance of ECFpGroupParams since this function is only used by SCAPI.
	ECFpGroupParams * fpParams = (ECFpGroupParams *)params;
	
	// create the ECCurve - convert the accepted parameters to MIRACL parameters 
	biginteger p = fpParams->getP();
	Big bigp = biginteger_to_big(p);
	Big biga = biginteger_to_big(fpParams->getA() % p);
	Big bigb = biginteger_to_big(fpParams->getB());

	/* initialize the curve */
	ecurve_init(biga.getbig(), bigb.getbig(), bigp.getbig(), 2);

	//mirkill(biga.getbig()); // TODO - this throws exception from some reason
	//mirkill(bigp.getbig());
	//mirkill(bigb.getbig());

	// create the generator
	generator = new ECFpPointMiracl(fpParams->getXg(), fpParams->getYg(), this);
}

bool MiraclDlogECFp::basicAndInfinityChecksForExpForPrecomputedValues(GroupElement * base) {
	// if the GroupElements does not match the DlogGroup, throw exception
	auto baseECFp = dynamic_cast<ECFpPointMiracl *>(base);
	if (!baseECFp)
		throw invalid_argument("groupElement doesn't match the DlogGroup");

	// infinity remains the same after any exponentiate
	return baseECFp->isInfinity();				
}

ebrick * MiraclDlogECFp::initExponentiateWithPrecomputedValues(GroupElement * baseElement, biginteger exponent, int window, int maxBits) {
	ECFpGroupParams * params = (ECFpGroupParams * )getGroupParams();

	//translate parameters  to miracl notation
	biginteger p = params->getP();
	Big exponentB = biginteger_to_big(exponent);
	Big pB = biginteger_to_big(p); 
	Big aB = biginteger_to_big(params->getA() % p);
	Big bB = biginteger_to_big(params->getB());

	//Create a new structure to hold the precomputed values for given base and exponent
	ebrick* exponentiations = new ebrick();

	//Get the coordinates (x,y) from the requested base point: 
	big x, y;
	x = mirvar(0);
	y = mirvar(0);
	ECFpPointMiracl * base = dynamic_cast<ECFpPointMiracl *>(baseElement);
	epoint_get(base->getPoint(), x, y);

	//Perform precomputation
	ebrick_init(exponentiations, x, y, aB.getbig(), bB.getbig(), pB.getbig(), window, maxBits);

	//clean up
	mirkill(exponentB.getbig());
	mirkill(pB.getbig());
	mirkill(aB.getbig());
	mirkill(bB.getbig());

	//Return the pointer to the structure where the precomputed values are held
	return exponentiations;
}

GroupElement * MiraclDlogECFp::computeExponentiateWithPrecomputedValues(ebrick* ebrickPointer, biginteger exponent) {
	//translate parameters  to miracl notation
	Big exponentB = biginteger_to_big(exponent);

	//(x,y) are the coordinates of the point which is the result of the exponentiation
	big x, y;
	x = mirvar(0);
	y = mirvar(0);
	//calculates the required exponent
	mul_brick(ebrickPointer, exponentB.getbig(), x, y);

	//printf("The result of mul_brick(mip, exponentiations, exponent, x, y) is x=%d, y=%d\n", (*x).w,(*y).w);

	epoint* p = new epoint();
	p = epoint_init();
	epoint_set(x, y, 0, p);

	mirkill(x);
	mirkill(y);

	//Build a ECFpPointMiracl element from the result value
	return new ECFpPointMiracl(p, this);
}

GroupElement * MiraclDlogECFp::getInverse(GroupElement * groupElement) {
	//if the GroupElement doesn't match the DlogGroup, throw exception
	ECFpPointMiracl * ecm_point = dynamic_cast<ECFpPointMiracl *>(groupElement);
	if (!ecm_point)
		throw new invalid_argument("groupElement doesn't match the DlogGroup");

	// the inverse of infinity point is infinity
	if (ecm_point->isInfinity())
		return groupElement;

	epoint * point = ecm_point->getPoint();
	big x = mirvar(0);
	big y = mirvar(0);

	//init the result point and copy point values to it
	epoint* p2 = epoint_init();
	epoint_get(point, x, y);
	epoint_set(x, y, 0, p2);

	mirkill(x);
	mirkill(y);
	//inverse the point
	epoint_negate(p2);

	// build a ECFpPointMiracl element from the result value
	return new ECFpPointMiracl(p2, this);
}

GroupElement * MiraclDlogECFp::multiplyGroupElements(GroupElement * groupElement1, GroupElement * groupElement2) {
	ECFpPointMiracl * ecm_point1 = dynamic_cast<ECFpPointMiracl *>(groupElement1);
	ECFpPointMiracl * ecm_point2 = dynamic_cast<ECFpPointMiracl *>(groupElement2);
	// if the GroupElements don't match the DlogGroup, throw exception
	if (!ecm_point1 || !ecm_point2)
		throw invalid_argument("groupElement doesn't match the DlogGroup");

	//if one of the points is the infinity point, the second one is the multiplication result
	if (ecm_point1->isInfinity())
		return groupElement2;
	if (ecm_point2->isInfinity())
		return groupElement1;

	epoint * point1 = ecm_point1->getPoint();
	epoint * point2 = ecm_point2->getPoint();

	/* convert the accepted parameters to MIRACL parameters*/
	big x = mirvar(0);
	big y = mirvar(0);

	/* create the result point with the values of p2. This way, p2 values won't damage in the multiplication operation */
	epoint * point3 = epoint_init();
	epoint_get(point2, x, y);
	epoint_set(x, y, 0, point3);

	mirkill(x);
	mirkill(y);
	/* The multiply operation is converted to addition because miracl treat EC as additive group */
	ecurve_add(point1, point3);

	// build a ECFpPointMiracl element from the result value
	return new ECFpPointMiracl(point3, this);
}

GroupElement * MiraclDlogECFp::exponentiate(GroupElement * base, biginteger exponent){
	// if the GroupElements don't match the DlogGroup, throw exception
	ECFpPointMiracl * ecm_point = dynamic_cast<ECFpPointMiracl *>(base);
	if(!base)
		throw invalid_argument("groupElement doesn't match the DlogGroup");

	// infinity remains the same after any exponentiate
	if (ecm_point->isInfinity())
		return base;

	//If the exponent is negative, convert it to be the exponent modulus q.
	if (exponent < 0) 
		exponent = exponent % getOrder();

	epoint * point = ecm_point->getPoint();
	Big exp = biginteger_to_big(exponent);

	//init the result point
	epoint * p2 = epoint_init();

	/* The exponentiate operation is converted to multiplication because miracl treat EC as additive group */
	ecurve_mult(exp.getbig(), point, p2);

	//mirkill(exp.getbig());

	// build a ECFpPointMiracl element from the result value
	return new ECFpPointMiracl(p2, this);
}

GroupElement * MiraclDlogECFp::simultaneousMultipleExponentiations(vector<GroupElement *> groupElements, vector<biginteger> exponentiations) {
	int len = groupElements.size();

	// Our test results show that for elliptic curve over Fp and n<25 the naive algorithm gives the best performances
	if (len < 25)
		return computeNaive(groupElements, exponentiations);

	vector <epoint *> nativePoints(len);

	ECFpPointMiracl * ecm_point;
	for (int i = 0; i < len; i++) {
		// if the GroupElements don't match the DlogGroup, throw exception
		ecm_point = dynamic_cast<ECFpPointMiracl *>(groupElements[i]);
		if (!ecm_point)
			throw invalid_argument("groupElement doesn't match the DlogGroup");
		nativePoints[i] = ecm_point->getPoint();
	}

	vector<epoint *> points(len);
	vector<big> bigExponents(len);
	int i;
	epoint *p;
	for (i = 0; i<len; i++) {
		points[i] = nativePoints[i];
		bigExponents[i] = biginteger_to_big(exponentiations[i]).getbig();
	}

	p = m_computeLL(points, bigExponents, len, 1); // points and bigExponent are passed by reference as consts

	//release the memory
	for (i = 0; i<len; i++)
		mirkill(bigExponents[i]);

	// build a ECF2mPointMiracl element from the result value
	return new ECFpPointMiracl(p, this);
}

epoint* MiraclDlogECFp::m_computeLL(const vector<epoint*> &points, const vector<big> &exponents, int n, int field) {
	big bigExp = mirvar(0);
	big two = mirvar(2);
	big zero = mirvar(0);
	int t = 0, w, h, i, j;
	epoint *** preComp;
	epoint* result;

	// get the biggest exponent
	for (i = 0; i<n; i++)
		if (mr_compare(bigExp, exponents[i]) < 0)
			bigExp = exponents[i];
	
	// num of bitf in the biggest exponent
	t = logb2(bigExp);

	// choose w according to the value of t
	w = m_getLLW(t);

	// h = n/w
	if ((n % w) == 0)
		h = n / w;
	else
		h = ((int)(n / w)) + 1;

	// creates pre computation table - this allocate a lot of memory that need to be freed
	preComp = m_createLLPreCompTable(points, w, h, n, field);

	result = m_getIdentity(field); //holds the computation result		

	// computes the loop of the computation
	result = m_computeLoop(exponents, w, h, preComp, result, t - 1, n, field);

	//third part of computation
	for (j = t - 2; j >= 0; j--) {
		//operate y^2 differently. depends on the field type
		if (field == 1)
			ecurve_mult(two, result, result);
		else
			ecurve2_mult(two, result, result);
		// computes the loop of the computation
		result = m_computeLoop(exponents, w, h, preComp, result, j, n, field);
	}

	// free the allocated memeory
	mirkill(two);
	mirkill(zero);
	for (i = 0; i<h; i++) {
		for (j = 0; j<pow((double)2, w); j++) {
			epoint_free(preComp[i][j]);
		}
		free(preComp[i]);
	}
	free(preComp);

	return result;
}

int MiraclDlogECFp::m_getLLW(int t) {
	int w;
	//choose w according to the value of t
	if (t <= 10) {
		w = 2;
	}
	else if (t <= 24) {
		w = 3;
	}
	else if (t <= 60) {
		w = 4;
	}
	else if (t <= 144) {
		w = 5;
	}
	else if (t <= 342) {
		w = 6;
	}
	else if (t <= 797) {
		w = 7;
	}
	else if (t <= 1828) {
		w = 8;
	}
	else {
		w = 9;
	}
	return w;
}

epoint *** MiraclDlogECFp::m_createLLPreCompTable(const vector<epoint*> &points, int w, int h, int n, int field) {
	//create the pre-computation table of size h*(2^(w))
	int twoPowW = pow((double)2, w);
	
	// allocates memory for the table
	// create a big array to hold the points - need to allocate here a new memory
	epoint *** preComp = new epoint**[h];
	epoint* base = epoint_init();
	int baseIndex, k, e, i;


	for (i = 0; i < h; i++)
		preComp[i] = new epoint *[twoPowW];

	// fill the table
	epoint * id_point;
	for (k = 0; k<h; k++) {
		for (e = 0; e<twoPowW; e++) {
			id_point = m_getIdentity(field);
			preComp[k][e] = id_point;
			for (i = 0; i<w; i++) {
				baseIndex = k*w + i;
				if (baseIndex < n) {
					if (field == 1) {
						epoint_copy(points[baseIndex], base);
					}
					else {
						epoint2_copy(points[baseIndex], base);
					}
					if ((e & (1 << i)) != 0) { //bit i is set
						if (field == 1) {
							ecurve_add(base, id_point);
						}
						else {
							ecurve2_add(base, id_point);
						}
					}
				}
			}
		}
	}
	epoint_free(base);
	return preComp;
}


epoint* MiraclDlogECFp::m_getIdentity(int field) {
	big x, y;
	epoint* identity = epoint_init();

	x = mirvar(0);
	y = mirvar(0);
	//creation of the point depends on the field type
	if (field == 1)
		epoint_set(x, y, 0, identity);
	else
		epoint2_set(x, y, 0, identity);

	mirkill(x);
	mirkill(y);
	return identity;
}

epoint* MiraclDlogECFp::m_computeLoop(const vector<big> &exponentiations, int w, int h, epoint *** preComp, epoint* result, int bitIndex, int n, int field) {
	int e = 0, k, i, twoPow;
	big temp = mirvar(0);

	for (k = 0; k<h; k++) {
		for (i = k*w; i<(k * w + w); i++) {
			if (i < n) {
				copy(exponentiations[i], temp);

				// check if the bit in bitIndex is set.
				// shift the big number bitIndex times
				sftbit(temp, bitIndex*-1, temp);

				// check if the shifted big is divisible by two. if not - the first bit is set. 
				if (subdivisible(temp, 2) == 0) {
					twoPow = pow((double)2, i - k*w);
					e += twoPow;
				}
			}
		}

		//multiply operation depends on the field
		if (field == 1)
			ecurve_add(preComp[k][e], result);
		else
			ecurve2_add(preComp[k][e], result);
		e = 0;
	}
	mirkill(temp);
	return result;
}


GroupElement * MiraclDlogECFp::generateElement(bool bCheckMembership, vector<biginteger> values) {
	if (values.size() != 2) {
		throw invalid_argument("To generate an ECElement you should pass the x and y coordinates of the point");
	}
	return new ECFpPointMiracl(values[0], values[1], this);
}

bool MiraclDlogECFp::isMember(GroupElement * element) {

	// checks that the element is the correct object
	ECFpPointMiracl * point = dynamic_cast<ECFpPointMiracl *>(element);
	if (!point)
		throw invalid_argument("groupElement doesn't match the DlogGroup");

	// infinity point is a valid member
	if (point->isInfinity())
		return true;

	// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
	// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curves equation.
	// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
	// those two checks are done in two steps:
	// 1.	Checking that the point is on the curve, performed by checkCurveMembership
	// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership

	// The actual work is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
	// If we ever decide to change the implementation there will only be one place to change it.
	bool valid = util.checkCurveMembership((ECFpGroupParams *)groupParams, point->getX(), point->getY());
	valid = valid && util.checkSubGroupMembership(this, point);
	return valid;
}

ECElement * MiraclDlogECFp::getInfinity() {
	//create a point with the coordinates 0,0 which is the infinity point in miracl implementation
	big x, y;
	epoint* p = epoint_init();
	x = mirvar(0);
	y = mirvar(0);
	epoint_set(x, y, 0, p);
	mirkill(x);
	mirkill(y);
	return new ECFpPointMiracl(p, this);
}

void MiraclDlogECFp::endExponentiateWithPreComputedValues(GroupElement * base) {
	auto it = exponentiationsMap.find(base);
	if (it != exponentiationsMap.end()) {
		ebrick* ebrickPointer = it->second;
		ebrick_end(ebrickPointer);
		exponentiationsMap.erase(it);
	}
}

GroupElement * MiraclDlogECFp::encodeByteArrayToGroupElement(const vector<byte> & binaryString) {
	int len = binaryString.size();
	if (len > k)
		return 0;

	byte * byteString = new byte[len];
	copy_byte_vector_to_byte_array(binaryString, byteString, 0);
	big x, p;
	x = mirvar(0);
	p = getMip()->modulus;
	biginteger pi = ((ECFpGroupParams *)groupParams)->getP();
	cout << "got: " << pi << " from " << p << endl;
	int xx = logb2(p);
	//int l = logb2(p) / 8;
	getMip()->modulus = biginteger_to_big(pi).getbig();
	size_t l = bytesCount(pi);

	char* randomArray = new char[l - k - 2];
	char* newString = new char[l - k - 1 + len];

	memcpy(newString + l - k - 2, byteString, len);
	newString[l - k - 2 + len] = (char)len;

	int counter = 0;
	bool success = 0;

	csprng rng;
	srand(time(0));
	long seed;
	char raw = rand();
	time((time_t*)&seed);
	strong_init(&rng, 1, &raw, seed);
	do {

		for (int i = 0; i<l - k - 2; i++) {
			randomArray[i] = strong_rng(&rng);
		}

		memcpy(newString, randomArray, l - k - 2);

		bytes_to_big(l - k - 1 + len, newString, x);

		//If the number is negative, make it positive.
		if (exsign(x) == -1) {
			absol(x, x);
		}
		//epoint_x returns true if the given x value leads to a valid point on the curve.
		//if failed, go back to choose a random r etc.
		success = epoint_x(x);
		counter++;
	} while ((!success) && (counter <= 80)); //we limit the amount of times we try to 80 which is an arbitrary number.

	epoint* point = 0;
	if (success) {
		point = epoint_init();
		epoint_set(x, x, 0, point);
	}

	char* temp = new char[l - k - 1 + len];
	big_to_bytes(l - k - 1 + len, x, temp, 1);

	//Delete the allocated memory.
	mirkill(x);
	delete(randomArray);
	delete(newString);
	delete(byteString);

	//Return the created point.
	if (!point)
		return NULL;

	// Build a ECFpPointOpenSSL element from the result.
	return new ECFpPointMiracl(point, this);
}

const vector<byte> MiraclDlogECFp::decodeGroupElementToByteArray(GroupElement * groupElement) {
	ECFpPointMiracl * point = dynamic_cast<ECFpPointMiracl *>(groupElement);
	if (!point)
		throw invalid_argument("element type doesn't match the group type");
	
	size_t lenX = bytesCount(point->getX());
	byte * xByteArray = new byte[lenX];
	encodeBigInteger(point->getX(), xByteArray, lenX);
	byte bOriginalSize = xByteArray[lenX - 1];
	byte * b2 = new byte[bOriginalSize];
	vector<byte> result(bOriginalSize);
	result.insert(result.end(), &xByteArray[lenX - 1 - bOriginalSize], &xByteArray[lenX - 1]);
	//result->insert(result->end(), &xByteArray[0], &xByteArray[sizeX]);
	//result->insert(result->end(), &yByteArray[0], &xByteArray[sizeY]);
	//System.arraycopy(xByteArray, xByteArray.length - 1 - bOriginalSize, b2, 0, bOriginalSize);
	return result;
}
const vector<byte> MiraclDlogECFp::mapAnyGroupElementToByteArray(GroupElement * groupElement) {
	//This function simply returns an array which is the result of concatenating 
	//the byte array representation of x with the byte array representation of y.
	ECFpPointMiracl * point = dynamic_cast<ECFpPointMiracl *>(groupElement);
	if (!point)
		throw invalid_argument("element type doesn't match the group type");

	//The actual work is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
	//If we ever decide to change the implementation there will only be one place to change it.
	return *util.mapAnyGroupElementToByteArray(point->getX(), point->getY());
}

/****************************************************/
/******** ECFpPointMiracl Implementation ******/
/***************************************************/ 

ECFpPointMiracl::ECFpPointMiracl(biginteger x, biginteger y, MiraclDlogECFp * curve){
	//Create a point in the field with the given parameters, done by Miracl's native code.
	//Miracl always checks validity of (x,y).
	
	/* create the point with x,y values */
	epoint* p = epoint_init();
	Big b_x = biginteger_to_big(x);
	Big b_y = biginteger_to_big(y);

	bool valid = epoint_set(b_x.getbig(), b_y.getbig(), 0, p);

	//mirkill(b_x.getbig());
	//mirkill(b_y.getbig());

	//If the validity check done by Miracl did not succeed then this not a valid point
	if (!valid) {
		epoint_free(p);
		throw invalid_argument("x, y values are not a point on this curve");
	}
	
	//Keep the coordinates for performance reasons. See long comment above next to declaration.
	point = p;
	this->x = x;
	this->y = y;
}

ECFpPointMiracl::ECFpPointMiracl(epoint * ptr, MiraclDlogECFp * curve) {
	point = ptr;
	//Set X and Y coordinates:
	//in case of infinity, there are no coordinates and we set them to null
	if (point_at_infinity(ptr)) {
		x = NULL;
		y = NULL;
	}
	else {
		big bx = mirvar(0);
		big by = mirvar(0);
		epoint_get(point, bx, by);
		x = big_to_biginteger(bx);
		y = big_to_biginteger(by);
	}
}

bool ECFpPointMiracl::operator==(const GroupElement &other) const {
	if (typeid(*this) != typeid(other))
		return false;
	const ECFpPointMiracl * element = dynamic_cast<const ECFpPointMiracl *>(&other);

	return (element->getX() == this->getX()) && (element->getY() == getY());
}

bool ECFpPointMiracl::operator!=(const GroupElement &other) const {
	return !(*this == other);
}

ECFpPointMiracl::~ECFpPointMiracl() {
	epoint_free(point);
}