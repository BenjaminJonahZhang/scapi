#include "../../include/circuits/BooleanCircuits.hpp"

/****************************************************/
/*                    Gate                          */
/****************************************************/
void Gate::compute(map<int, Wire> & computedWires) {
	// we call the calculateIndexOfTruthTable method to tell us the position of the output value in the truth table 
	// and look up the value at that position.
	bool bVal = truthTable.at(calculateIndexOfTruthTable(computedWires));
	byte outputValue = (byte)(bVal ? 1 : 0);
	int numberOfOutputs = outputWireIndices.size();

	// assigns output value to each of this gate's output Wires.
	for (int i = 0; i < numberOfOutputs; i++)
		computedWires[outputWireIndices[i]] = Wire(outputValue);
}

bool Gate::operator==(const Gate &other) const {
	// first we verify that the gates' numbers are the same.
	if (gateNumber_ != other.gateNumber_)
		return false;

	// next we verify that the gates' respective truth tables are the same.
	if (truthTable != other.truthTable)
		return false;

	// next we verify that the number of input and output wires to the two respective gates are equal.
	if ((inputWireIndices.size() != other.inputWireIndices.size()) || (outputWireIndices.size() != other.outputWireIndices.size()))
		return false;

	/*
	* Having determined that the number of input Wire's are the same, we now check that corresponding input wires
	* have the same index. As we demonstrated above (in the comments on the imputWireIndices field), the order of the
	* wires is significant as not all functions are symmetric. So not only do we care that Wire have the same indices,
	* but we also care that the wires with the same index are in the same position of the inputWireIndices array.
	*/
	int numberOfInputs = inputWireIndices.size();
	for (int i = 0; i < numberOfInputs; i++)
		if (inputWireIndices[i] != other.inputWireIndices[i])
			return false;

	/*
	* Having determined that the number of output Wire's are the same, we now check that corresponding output wires have
	* the same index.
	*/
	int numberOfOutputs = outputWireIndices.size();
	for (int i = 0; i < numberOfOutputs; i++)
		if (outputWireIndices[i] != other.outputWireIndices[i])
			return false;

	// If we've reached this point, then the Gate's are equal so we return true.
	return true;
}

int Gate::calculateIndexOfTruthTable(map<int, Wire> computedWires) const {
	/*
	* Since a truth tables order is the order of binary counting, the index of a desired row can be calculated as follows:
	* For a truth table with L inputs whose input columns are labeled aL...ai...a2,a1,
	* the output index for a given input set is given by: summation from 0 to L : ai *2^i.
	* This is calculated below:
	*/
	int truthTableIndex = 0;
	int numberOfInputs = inputWireIndices.size();
	for (int i = numberOfInputs - 1, j = 0; j < numberOfInputs; i--, j++) 
		truthTableIndex += computedWires[inputWireIndices[i]].getValue() * pow(2, j);
	return truthTableIndex;
}

/****************************************************/
/*                BooleanCircuit                    */
/****************************************************/

//public BooleanCircuit(Scanner s) throws CircuitFileFormatException {
//	//Read the number of gates.
//	int numberOfGates = Integer.parseInt(read(s));
//	gates = new Gate[numberOfGates];
//	//Read the number of parties.
//	numberOfParties = Integer.parseInt(read(s));
//	isInputSet = new boolean[numberOfParties];
//	//For each party, read the party's number, number of input wires and their indices.
//	for (int i = 0; i < numberOfParties; i++) {
//		if (Integer.parseInt(read(s)) != i + 1) {//add 1 since parties are indexed from 1, not 0
//			throw new CircuitFileFormatException();
//		}
//		//Read the number of input wires.
//		int numberOfInputsForCurrentParty = Integer.parseInt(read(s));
//		if (numberOfInputsForCurrentParty < 0) {
//			throw new CircuitFileFormatException();
//		}
//		boolean isThisPartyInputSet = numberOfInputsForCurrentParty == 0 ? true : false;
//		isInputSet[i] = isThisPartyInputSet;
//
//		ArrayList<Integer> currentPartyInput = new ArrayList<Integer>();
//		eachPartysInputWires.add(currentPartyInput);
//		//Read the input wires indices.
//		for (int j = 0; j < numberOfInputsForCurrentParty; j++) {
//			currentPartyInput.add(Integer.parseInt(read(s)));
//		}
//	}
//
//	/*
//	* The ouputWireIndices are the outputs from this circuit. However, this circuit may actually be a single layer of a
//	* larger layered circuit. So this output can be part of the input to another layer of the circuit.
//	*/
//	int numberOfCircuitOutputs = Integer.parseInt(read(s));
//	outputWireIndices = new int[numberOfCircuitOutputs];
//	//Read the output wires indices.
//	for (int i = 0; i < numberOfCircuitOutputs; i++) {
//		outputWireIndices[i] = Integer.parseInt(read(s));
//	}
//
//	int numberOfGateInputs, numberOfGateOutputs;
//	//For each gate, read the number of input and output wires, their indices and the truth table.
//	for (int i = 0; i < numberOfGates; i++) {
//		numberOfGateInputs = Integer.parseInt(read(s));
//		numberOfGateOutputs = Integer.parseInt(read(s));
//		int[] inputWireIndices = new int[numberOfGateInputs];
//		int[] outputWireIndices = new int[numberOfGateOutputs];
//		for (int j = 0; j < numberOfGateInputs; j++) {
//			inputWireIndices[j] = Integer.parseInt(read(s));
//		}
//		for (int j = 0; j < numberOfGateOutputs; j++) {
//			outputWireIndices[j] = Integer.parseInt(read(s));
//		}
//
//		/*
//		* We create a BitSet representation of the truth table from the 01 String
//		* that we read from the file.
//		*/
//		BitSet truthTable = new BitSet();
//		String tTable = read(s);
//		for (int j = 0; j < tTable.length(); j++) {
//			if (tTable.charAt(j) == '1') {
//				truthTable.set(j);
//			}
//		}
//		//Construct the gate.
//		gates[i] = new Gate(i, truthTable, inputWireIndices, outputWireIndices);
//	}
//}