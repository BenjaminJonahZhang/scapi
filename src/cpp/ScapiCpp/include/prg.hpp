#ifndef SCAPI_PRG_H
#define SCAPI_PRG_H

#include "Common.hpp"
#include "Key.hpp"
#include "prf.hpp"
#include "Factories.hpp"

/**
* Parameters for PrgFromPrf key generation.
*/
class PrgFromPrfParameterSpec : public AlgorithmParameterSpec {
private:
	vector<byte> entropySource;	// random bit sequence.=
	int prfKeySize;		// Prf key size in bits.

public:	
	/**
	* Constructor that gets a random bit sequence which is the entropy source, and prf key size in bits and sets them.
	*/
	PrgFromPrfParameterSpec(vector<byte> entropySource, int prfKeySize) {
		this->entropySource = entropySource;
		this->prfKeySize = prfKeySize;
	};
	vector<byte> getEntropySource() { return entropySource; };
	int getPrfKeySize() { return prfKeySize; };
};

/**
* General interface of pseudorandom generator. Every concrete class in this family should implement this interface. <p>
*
* A pseudorandom generator (PRG) is a deterministic algorithm that takes a short uniformly distributed string,
* known as the seed, and outputs a longer string that cannot be efficiently distinguished from a uniformly
* distributed string of that length.
*/
class PseudorandomGenerator {
public:
	/**
	* Sets the secret key for this prg.
	* The key can be changed at any time.
	*/
	virtual void setKey(SecretKey secretKey)=0;
	/**
	* An object trying to use an instance of prg needs to check if it has already been initialized with a key.
	* @return true if the object was initialized by calling the function setKey.
	*/
	virtual bool isKeySet()=0;
	/**
	* @return the algorithm name. For example - RC4
	*/
	virtual string getAlgorithmName()=0;
	/**
	* Generates a secret key to initialize this prg object.
	* @param keyParams algorithmParameterSpec contains the required parameters for the key generation
	* @return the generated secret key
	*/
	virtual SecretKey generateKey(AlgorithmParameterSpec keyParams)=0;
	/**
	* Generates a secret key to initialize this prg object.
	* @param keySize is the required secret key size in bits
	* @return the generated secret key
	*/
	virtual SecretKey generateKey(int keySize)=0;
	/**
	* Streams the prg bytes.
	* @param outBytes - output bytes. The result of streaming the bytes.
	* @param outOffset - output offset
	* @param outlen - the required output length
	*/
	virtual void getPRGBytes(vector<byte> & outBytes, int outOffset, int outlen)=0;
};

/**
* Marker interface. Each RC4 concrete class should implement this interface.
*/
class RC4 : public PseudorandomGenerator {};

/**
* This is a simple way of generating a pseudorandom stream from a pseudorandom function. The seed for the pseudorandom generator is the key to the pseudorandom function.
* Then, the algorithm initializes a counter to 1 and applies the pseudorandom function to the counter, increments it, and repeats.
*/
class ScPrgFromPrf : public PseudorandomGenerator {
private:
	PseudorandomFunction * prf;	// Underlying PRF.
	vector<byte> ctr;			// Counter used for key generation.
	bool isKeySet;
	/**
	* Increases the ctr byte array by 1 bit.
	*/
	void increaseCtr();

public:
	/**
	* Constructor that lets the user choose the underlying PRF algorithm.
	* @param prf underlying PseudorandomFunction.
	*/
	ScPrgFromPrf(PseudorandomFunction * prf) {prf = prf; };
	/**
	* Constructor that lets the user choose the underlying PRF algorithm.
	* @param prfName PseudorandomFunction algorithm name.
	*/
	ScPrgFromPrf(string prfName) : ScPrgFromPrf(PrfFactory.getInstance().getObject(prfName)) {};

	void setKey(SecretKey secretKey) override;
	bool isKeySet() override { return isKeySet; };
	string getAlgorithmName() override { return "PRG_from_" + prf->getAlgorithmName(); };
	SecretKey generateKey(AlgorithmParameterSpec keyParams) override { return prf->generateKey(keyParams); };
	SecretKey generateKey(int keySize) override { return prf->generateKey(keySize); };
	void getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen) override;
}


#endif