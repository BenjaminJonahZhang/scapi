#pragma once
#include "../infra/Common.hpp"
#include "../primitives/Dlog.hpp"

/**
* This is a marker interface. It allows the generation of an AsymmetricCiphertext at
* an abstract level.
*/
class PlaintextSendableData {};


/**
* This is a marker interface for all plain-texts.
*/
class Plaintext {
public:
	/**
	* This function is used when a Plaintex needs to be sent via 
	* a Channel or any other means of sending data (including serialization).
	* It retrieves all the data needed to reconstruct this Plaintext at a later time
	* and/or in a different environment.
	* It puts all the data in an instance of the relevant class that implements the
	* PlaintextSendableData interface.
	* @return the PlaintextSendableData object
	*/
	virtual PlaintextSendableData* generateSendableData()=0;
};

/**
* This class holds the plaintext as a BigInteger.
*/
class BigIntegerPlainText : public Plaintext, public PlaintextSendableData {
private:
	biginteger x;

public:
	biginteger getX() const { return x; };
	BigIntegerPlainText(biginteger x) { this->x = x; };
	BigIntegerPlainText(string s) { this->x = biginteger(s); };
	bool operator==(const BigIntegerPlainText &other) const {
		const biginteger x1 = other.getX();
		return (x1==x);
	};

	PlaintextSendableData* generateSendableData() override {
		// since BigIntegerPlainText is both a Plaintext and a PlaintextSendableData, 
		// on the one hand it has to implement the generateSendableData() function, 
		// but on the other hand it is in itself an PlaintextSendableData, so we do not really
		// generate sendable data, but just return this object.
		return this;
	}

	string toString() { return "BigIntegerPlainText [x=" + (string)x + "]"; };
};

/**
* This class holds the plaintext as a ByteArray.
*/
class ByteArrayPlaintext : public Plaintext, public PlaintextSendableData {
private:
	byte* text = NULL;
	int len;
public:
	ByteArrayPlaintext(byte* text, int size) { this->text = text; this->len = size; };
	byte* getText() const { return text; };
	int getTextSize() const { return len; };

	bool operator==(const ByteArrayPlaintext &other) const {
		byte* text2 = other.getText();
		int len2 = other.getTextSize();
		if (len2 != len)
			return false;
		for (int i = 0; i<len; i++)
			if (text[i] != text2[i])
				return false;
		return true;
	};
	PlaintextSendableData* generateSendableData() override {
		// since ByteArrayPlainText is both a Plaintext and a PlaintextSendableData, 
		// on the one hand it has to implement the generateSendableData() function, 
		// but on the other hand it is in itself an PlaintextSendableData, so we do not really
		// generate sendable data, but just return this object.
		return this;
	};

	string toString() {
		return "ByteArrayPlaintext [text=" + 
			std::string(reinterpret_cast<char const*>(text), len) + "]";
	};
};

/**
* This class holds the plaintext as a GroupElement.
*/
class GroupElementPlaintext : public Plaintext {
private:
	GroupElement* element;

public:
	GroupElementPlaintext(GroupElement* el) { element = el; };
	GroupElement* getElement() const { return element; };

	bool operator==(const GroupElementPlaintext &other) const {
		return (*(other.getElement()) == *(this->getElement()));
	};

	PlaintextSendableData* generateSendableData() override {
		return new GroupElementPlaintextSendableData(element->generateSendableData());
	}

	// Nested class that holds the sendable data of the outer class
	class GroupElementPlaintextSendableData : public PlaintextSendableData {
	private:
		GroupElementSendableData*  groupElementData;
	public:
		GroupElementPlaintextSendableData(GroupElementSendableData* groupElementData) {
			this->groupElementData = groupElementData;
		};

		GroupElementSendableData* getGroupElement() { return groupElementData; };
	};
};

