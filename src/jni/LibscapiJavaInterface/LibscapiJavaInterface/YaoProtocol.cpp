#include "YaoProtocol.h"
#include <libscapi\protocols\SemiHonestYao\YaoParties.hpp>

JNIEXPORT jlong JNICALL Java_edu_biu_SCProtocols_NativeSemiHonestYao_YaoParty_createYaoParty
(JNIEnv *env, jobject, jint id, jstring configFileName) {
	//Convert the jni objects to c++ objects.
	const char* configFile = env->GetStringUTFChars(configFileName, NULL);
	cout << "config file = " << configFile << endl;
	YaoConfig yao_config(configFile);
	cout << "after yao config" << endl;
	if (id == 1) {
		PartyOne * p1 = new PartyOne(yao_config);
		return (long)p1;
	} else if (id == 2) {
		PartyTwo * p2 = new PartyTwo(yao_config);
		return (long)p2;
	}
}

JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_NativeSemiHonestYao_YaoParty_runProtocol
(JNIEnv *env, jobject, jint number_of_iterations, jint id, jlong party) {
	cout << "in native run protocol" << endl;
	cout << "number_of_iterations = " << number_of_iterations << endl;
	cout << "id = " << id << endl;
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