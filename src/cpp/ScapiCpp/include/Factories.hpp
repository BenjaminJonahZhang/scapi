#pragma once

#include "Common.hpp"
#include "prf.hpp"

class PrfFactory {
public:
	static PrfFactory & getInstance() {
		static PrfFactory instance; /// Guaranteed to be destroyed.  Instantiated on first use.
		return instance;
	};
	/**
	* @param provider the required provider name
	* @param algName the required algorithm name
	* @return an object of type PseudorandomFunction class that was determined by the algName + provider
	*/
	PseudorandomFunction * getObject(string algName, string provider);
	/**
	* @return an object of type PseudorandomFunction class that was determined by the algName + the default provider for that algorithm.
	*/
	PseudorandomFunction * getObject(string algName);

private:

	PrfFactory() {};
	// We can use the better technique of deleting the methods
	// we don't want.
	PrfFactory(PrfFactory const&) = delete;
	void operator=(PrfFactory const&) = delete;
	
	
	//private static PrfFactory instance = new PrfFactory();;
	//private FactoriesUtility factoriesUtility;


	///**
	//* Private constructor since this class is of the singleton pattern.
	//* It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
	//* of FactoriesUtility.
	//*
	//*/
	//private PrfFactory() {

	//	//create an instance of FactoriesUtility with the predefined file names.
	//	factoriesUtility = new FactoriesUtility("PrfDefault.properties", "Prf.properties");

	//}
};
