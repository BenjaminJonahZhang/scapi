#include "YaoProtocol.h"
#include <libscapi/protocols/SemiHonestYao/YaoParties.hpp>

/**
 * Create the Yao party.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_SCProtocols_NativeSemiHonestYao_YaoParty_createYaoParty
(JNIEnv *env, jobject, jint id, jstring configFileName) {
	//Convert the jni objects to c++ objects.
	const char* configFile = env->GetStringUTFChars(configFileName, NULL);
	YaoConfig yao_config(configFile);
	if (id == 1) {
		PartyOne * p1 = new PartyOne(yao_config);
		p1->setInputs(yao_config.input_file_1);
		return (long)p1;
	} else if (id == 2) {
		PartyTwo * p2 = new PartyTwo(yao_config);
		p2->setInputs(yao_config.input_file_2);
		return (long)p2;
	}
}

/**
 *  Run the protocol according the number of execution given in the config file.
 * In case of party two, the output is the output of the circuit.
 * In case of party one, the output is an empty array. (p1 has no input in this protocol)
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_NativeSemiHonestYao_YaoParty_runProtocol
(JNIEnv *env, jobject,  jint id, jlong party) {
	
	int number_of_iterations;
	if (id == 1)
		number_of_iterations = ((PartyOne*)party)->getConfig().number_of_iterations;
	else if (id == 2)
		number_of_iterations = ((PartyTwo*)party)->getConfig().number_of_iterations;

	auto all = scapi_now();
	for (int i = 0; i < number_of_iterations; i++) {
		// run the protocol
		if (id == 1)
			((PartyOne*)party)->run();
		else if (id == 2)
			((PartyTwo*)party)->run();
	}
	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
	cout << "Running " << number_of_iterations <<
		" iterations took: " << elapsed_ms << " milliseconds" << endl
		<< "Average time per iteration: " << elapsed_ms / (float)number_of_iterations << " milliseconds" << endl;

	//Create a jni object and fill it with the protocol output.
	jbyteArray result = env->NewByteArray(0);
	
	if (id == 2) {
		auto output = ((PartyTwo*)party)->getOutput();
		result = env->NewByteArray(output.size());
		env->SetByteArrayRegion(result, 0, output.size(), (jbyte*)output.data());
	}

	//Return the output
	return result;
}

/**
 * Delete the allocated memory.
 */
JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_NativeSemiHonestYao_YaoParty_deleteYao
(JNIEnv *, jobject, jint id, jlong party) {
	if (id == 1)
		delete (PartyOne*)party;
	else if (id == 2)
		delete (PartyTwo*)party;
}