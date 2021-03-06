/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
#include <libscapi/protocols/YaoSingleExecution/YaoSEParty.h>
#include <libscapi/include/infra/CircuitConverter.hpp>

/* Header for class edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty */

#ifndef _Included_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty
#define _Included_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty
#ifdef __cplusplus
extern "C" {
#endif
	/*
	* Class:     edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty
	* Method:    createYaoSEParty
	* Signature: (ILjava/lang/String;Ljava/lang/String;ILjava/lang/String;)J
	*/
	JNIEXPORT jlong JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_createYaoSEParty
		(JNIEnv *, jobject, jint, jstring, jstring, jint, jstring);

	/*
	* Class:     edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty
	* Method:    runProtocol
	* Signature: (J)[B
	*/
	JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_runProtocol
		(JNIEnv *, jobject, jlong);

	/*
	* Class:     edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty
	* Method:    runOfflineProtocol
	* Signature: (J)V
	*/
	JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_runOfflineProtocol
		(JNIEnv *, jobject, jlong);

	/*
	* Class:     edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty
	* Method:    runOnlineProtocol
	* Signature: (J)[B
	*/
	JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_runOnlineProtocol
		(JNIEnv *, jobject, jlong);

	/*
	* Class:     edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty
	* Method:    deleteYaoSE
	* Signature: (J)V
	*/
	JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_YaoSingleExecution_YaoSEParty_deleteYaoSE
		(JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif
