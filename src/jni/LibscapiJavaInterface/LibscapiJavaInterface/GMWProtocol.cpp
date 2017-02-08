//
// Created by moriya on 31/01/17.
//
#include "GMWProtocol.h"
#include <libscapi/protocols/GMW/GMWParty.h>
#include <libscapi/protocols/GMW/Circuit.h>


JNIEXPORT jlong JNICALL Java_edu_biu_SCProtocols_gmw_GmwParty_createGMWParty
        (JNIEnv *env, jobject, jint id , jstring circuitFileName, jstring partiesFileName, jstring inputsFileName, jint numThreads){

	//Convert the jni objects to c++ objects.
	const char* circuitFile = env->GetStringUTFChars(circuitFileName, NULL);
	const char* partiesFile = env->GetStringUTFChars(partiesFileName, NULL);
	const char* inputFile = env->GetStringUTFChars(inputsFileName, NULL);

	//Create the circuit
    shared_ptr<Circuit> circuit = make_shared<Circuit>();
    circuit->readCircuit(circuitFile);

	//Create the GMW party. This is the class that executes the protocol.
    GMWParty* party = new GMWParty(id, circuit, partiesFile, numThreads, inputFile);
	
	//Return a pointer to the protocol object.
    return (long) party;
}

JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_gmw_GmwParty_runProtocol
		(JNIEnv *env, jobject, jlong party){

	//Run the protocol/
    ((GMWParty*)party)->runOffline();
    auto output = ((GMWParty*)party)->runOnline();
	
	//Create a jni object and fill it with the protocol output.
	jbyteArray result = env->NewByteArray(output.size());
	env->SetByteArrayRegion(result, 0, output.size(), (jbyte*)output.data());

	//Return the output
	return result;
}

JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_gmw_GmwParty_deleteGMW
(JNIEnv *, jobject, jlong party) {
	delete (GMWParty*)party;
}