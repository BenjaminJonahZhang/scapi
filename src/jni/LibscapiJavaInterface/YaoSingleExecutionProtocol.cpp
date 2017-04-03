#include "YaoSingleExecutionProtocol.h"


JNIEXPORT jlong JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_createYaoSEParty
(JNIEnv * env, jobject, jint id, jstring circuitFileName, jstring ipAddress, jint port, jstring inputsFileName) {

	//Convert the jni objects to c++ objects.
	const char* circuitFile = env->GetStringUTFChars(circuitFileName, NULL);
	const char* ip = env->GetStringUTFChars(ipAddress, NULL);
	const char* inputFile = env->GetStringUTFChars(inputsFileName, NULL);

	string newCircuit = "emp_format_circuit.txt";
	CircuitConverter::convertScapiToBristol(circuitFile, newCircuit, false);

	//Create the GMW party. This is the class that executes the protocol.
	YaoSEParty* party = new YaoSEParty(id, newCircuit, ip, port, inputFile);

	//Return a pointer to the protocol object.
	return (long)party;
}

JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_runProtocol
(JNIEnv *env, jobject, jlong party) {
	//Run the protocol/
	((YaoSEParty*)party)->run();
	auto output = ((YaoSEParty*)party)->getOutput();

	//Create a jni object and fill it with the protocol output.
	jbyteArray result = env->NewByteArray(output.size());
	env->SetByteArrayRegion(result, 0, output.size(), (jbyte*)output.data());

	//Return the output
	return result;
}

JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_runOfflineProtocol
(JNIEnv *, jobject, jlong party) {
	//Run the protocol/
	((YaoSEParty*)party)->runOffline();
}

JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_runOnlineProtocol
(JNIEnv *env, jobject, jlong party) {
	//Run the protocol/
	((YaoSEParty*)party)->runOnline();
	auto output = ((YaoSEParty*)party)->getOutput();

	//Create a jni object and fill it with the protocol output.
	jbyteArray result = env->NewByteArray(output.size());
	env->SetByteArrayRegion(result, 0, output.size(), (jbyte*)output.data());

	//Return the output
	return result;
}

JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_deleteYaoSE
(JNIEnv *, jobject, jlong party) {
	delete (YaoSEParty*)party;
}