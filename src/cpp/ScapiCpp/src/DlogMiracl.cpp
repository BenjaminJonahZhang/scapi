#include "../include/DlogMiracl.hpp"

miracl * MiraclAdapterDlogEC::getMip() {
	if (!mip)
		mip = mirsys(400, 16); 
	return mip;
}

MiraclAdapterDlogEC::~MiraclAdapterDlogEC()
{
	mirexit(mip); // should be mirexit(); 
}

void MiraclDlogECFp::doInit(CfgMap ecProperties, string curveName) {
	ECFpUtility util;
	this->groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
	//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
	biginteger p = ((ECFpGroupParams *)groupParams)->getP();
	k = util.calcK(p);
	createUnderlyingCurveAndGenerator(groupParams);
}

