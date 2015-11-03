#include "../include/Prf.hpp"

void PrpFromPrfFixed::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > inBytes.size()) || (inOff + inLen > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + outLen > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	// if the input and output length are equal to the blockSize, call the computeBlock that doesn't take length arguments.
	if (inLen == outLen && inLen == getBlockSize())
		computeBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("input and output lengths should be equal to Block size");
}

void PrpFromPrfFixed::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > inBytes.size()) || (inOff + inLen > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + getBlockSize() > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	// if the input and output length are equal to the blockSize, call the computeBlock that doesn't take length arguments.
	if (inLen == getBlockSize())
		this->computeBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("input and output lengths should be equal to Block size");
}

void PrpFromPrfFixed::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > inBytes.size()) || (inOff + len > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + len > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");
	// checks that the offset and length are correct 
	if (len == getBlockSize())//the length is correct
		//call the derived class implementation of invertBlock ignoring len
		invertBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("the length should be the same as block size");

}


void IteratedPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> & outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw invalid_argument("secret key isn't set");
	
	// checks that the offset and length are correct 
	if ((inOff > inBytes.size()) || (inOff + inLen > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + outLen > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	int prfLength = prfVaryingInputLength->getBlockSize(); // the output size of the prfVaryingInputLength
	int rounds = (int) ceil((float)outLen / (float)prfLength);  // the smallest integer for which rounds * prfLength > outlen
	vector<byte> intermediateOutBytes(prfLength); // round result
	vector<byte> currentInBytes(inBytes.begin() + inOff, inBytes.begin() + inOff + inLen); 	//copies the x (inBytes) to the input of the prf in the beginning
	currentInBytes.push_back((byte)outLen); // works for len up to 256 	//copies the outLen to the input of the prf after the x

	int bulk_size;
	int start_index;
	for (int i = 1; i <= rounds; i++) {
		currentInBytes.push_back((byte)i); // works for len up to 256 	//copies the i to the input of the prf
		// operates the computeBlock of the prf to get the round output
		prfVaryingInputLength->computeBlock(currentInBytes, 0, inLen + 2, intermediateOutBytes, 0);
		// copies the round result to the output byte array
		start_index = outOff + (i - 1)*prfLength;
		// in case of the last round - copies only the number of bytes left to match outLen
		bulk_size = (i == rounds) ? outLen - ((i - 1)*prfLength) : prfLength; 
		for (int j = 0; j < bulk_size; j++)
			outBytes[start_index+j] = intermediateOutBytes[j];
	}
}

LubyRackoffPrpFromPrfVarying::LubyRackoffPrpFromPrfVarying(){
	prfVaryingIOLength = new IteratedPrfVarying();
}

LubyRackoffPrpFromPrfVarying::LubyRackoffPrpFromPrfVarying(string prfVaryingIOLengthName) {
	throw NotImplementedException("factories still not implemented");
}

LubyRackoffPrpFromPrfVarying::LubyRackoffPrpFromPrfVarying(PrfVaryingIOLength * _prfVaryingIOLength) {
	auto test = dynamic_cast<LubyRackoffPrpFromPrfVarying *>(_prfVaryingIOLength);
	if (test)
		throw invalid_argument("Cannot create a LubyRackoffPrpFromPrfVarying from a LubyRackoffPrpFromPrfVarying object!");
	prfVaryingIOLength = prfVaryingIOLength;
}

void LubyRackoffPrpFromPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > inBytes.size()) || (inOff + inLen > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + inLen > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");
	if (inLen % 2 != 0) // checks that the input is of even length.
		throw invalid_argument("Length of input must be even");

	int sideSize = inLen / 2; // L in the pseudo code
	vector<byte> * tmpReference = NULL;
	vector<byte> * leftNext = new vector<byte>(sideSize);
	vector<byte> * rightNext = new vector<byte>(sideSize+1);//keeps space for the index. Size of L+1.

	// Let left_current be the first half bits of the input
	vector<byte> * leftCurrent = new vector<byte>(inBytes.begin()+inOff, inBytes.begin() + inOff + sideSize);

	//Let right_current be the last half bits of the input
	vector<byte> * rightCurrent = new vector<byte>(inBytes.begin() + inOff + sideSize, inBytes.begin() + inOff + 2 * sideSize);

	for (int i = 1; i <= 4; i++) {
		// Li = Ri-1
		leftNext->insert(rightCurrent->begin(), leftNext->begin(), rightCurrent->begin() + sideSize);

		// put the index in the last position of Ri-1
		rightCurrent->push_back((byte)i);

		// does PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
		// puts the result in the rightNext array. Later we will XOr it with leftCurrent. Note that the result size is not the entire
		// rightNext array. It is one byte less. The remaining byte will contain the index for the next iteration.
		prfVaryingIOLength->computeBlock(*rightCurrent, 0, rightCurrent->size(), *rightNext, 0, sideSize);

		// does Ri = Li-1 ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
		// XOR rightNext (which is the resulting PRF computation by now) with leftCurrent.
		for (int j = 0; j<sideSize; j++)
			(*rightNext)[j] = (byte)((*rightNext)[j] ^ (*leftCurrent)[j]);


		//switches between the current and the next for the next round.
		//Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
		//However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
		//Since both current and next will point to the same memory block and thus changing one will change the other.
		tmpReference = leftCurrent;
		leftCurrent = leftNext;
		leftNext = tmpReference;

		tmpReference = rightCurrent;
		rightCurrent = rightNext;
		rightNext = tmpReference;
	}

	// copies the result to the out array.
	outBytes.insert(outBytes.begin() + outOff, leftCurrent->begin(), leftCurrent->begin() + (inLen / 2));
	outBytes.insert(outBytes.begin() + outOff+inLen/2, rightCurrent->begin(), rightCurrent->begin() + (inLen / 2));

	delete leftCurrent, leftNext, rightCurrent, rightNext; // no need to delete tmpRefernece points to rightNext
}

void LubyRackoffPrpFromPrfVarying::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len){
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > inBytes.size()) || (inOff + len  > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + len > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");
	if (len % 2 != 0) // checks that the input is of even length.
		throw invalid_argument("Length of input must be even");

	int sideSize = len / 2; // L in the pseudo code
	vector<byte> * tmpReference = NULL;
	vector<byte> * leftCurrent = new vector<byte>(sideSize);
	vector<byte> * rightCurrent = new vector<byte>(sideSize + 1); //keeps space for the index. Size of L+1.

	// let leftNext be the first half bits of the input
	vector<byte> * leftNext = new vector<byte>(inBytes.begin() + inOff, inBytes.begin() + inOff + sideSize);
	// let rightNext be the last half bits of the input
	vector<byte> * rightNext = new vector<byte>(inBytes.begin() + inOff + sideSize, inBytes.begin() + inOff + 2*sideSize);

	for (int i = 4; i >= 1; i--) {
		//Ri-1 = Li
		rightCurrent->insert(rightCurrent->begin(), leftNext->begin(), leftNext->begin() + sideSize);
		rightCurrent->push_back((byte)i);


		// does PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
		// puts the result in the leftCurrent array. Later we will XOr it with rightNext. 
		prfVaryingIOLength->computeBlock(*rightCurrent, 0, rightCurrent->size(), *leftCurrent, 0, sideSize);

		// does Li-1 = Ri ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
		// XOR leftCurrent (which is the resulting PRF computation by now) with rightNext.
		for (int j = 0; j<sideSize; j++)
			(*leftCurrent)[j] = (byte)((*leftCurrent)[j] ^ (*rightNext)[j]);

		// switches between the current and the next for the next round.
		// Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
		// However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
		// since both current and next will point to the same memory block and thus changing one will change the other.
		tmpReference = leftNext;
		leftNext = leftCurrent;
		leftCurrent = tmpReference;

		tmpReference = rightNext;
		rightNext = rightCurrent;
		rightCurrent = tmpReference;

	}

	// copies the result to the out array.
	outBytes.insert(outBytes.begin() + outOff, leftNext->begin(), leftNext->begin()+sideSize);
	outBytes.insert(outBytes.begin() + outOff + sideSize, rightNext->begin(), rightNext->begin() + sideSize);

	delete leftCurrent, leftNext, rightCurrent, rightNext; // no need to delete tmpRefernece points to rightNext
}


void PrpFromPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("to use this prp, call the computeBlock function that specifies the block size length");
}

void PrpFromPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw new IllegalStateException("secret key isn't set");
	// checks that the offsets and lengths are correct 
	if ((inOff > inBytes.size()) || (inOff + inLen > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + outLen > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	//if the input and output lengths are equal, call the computeBlock which takes just one length argument
	if (inLen == outLen)
		computeBlock(inBytes, inOff, inLen, outBytes, outOff);

	else throw out_of_range("input and output lengths should be equal");

}

void PrpFromPrfVarying::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("to use this prp, call the invertBlock function which specify the block size length");
}
