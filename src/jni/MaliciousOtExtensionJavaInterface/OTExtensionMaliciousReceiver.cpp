#include "OTExtensionMaliciousReceiver.h"
#include "OTExtensionMaliciousReceiverInterface.h"
#include <jni.h>
#include <iostream>

using namespace maliciousot;
using std::cout;
using std::endl;

/*
 * Function initOtReceiver : This function initializes the receiver object and 
 * creates the connection with the sender
 * 
 * param ipAddress : The ip address of the receiver computer for connection
 * param port : The port to be used for sending/receiving data over the network
 * returns : A pointer to the receiver object that was created and later be used to run the protcol
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otBatch_otExtension_OTExtensionMaliciousReceiver_initOtReceiver(
JNIEnv *env, jobject, jstring ipAddress, jint port, jint numOfthreads, jint nbaseots, jint numOTs) {

    // get the ip address from java
    const char* address = env->GetStringUTFChars(ipAddress, NULL);
    //cout << "initOtReceiver(" << address << "," << port << ")" << endl;

    OtExtensionMaliciousReceiverInterface * receiver_interface;
    receiver_interface = new OtExtensionMaliciousReceiverInterface(address,
								   (int) port,
								   (int) numOfthreads,
								   (int) nbaseots, 
								   (int) numOTs);
    receiver_interface->init_ot_receiver();

    //cout << "finished initOtReceiver." << endl;
    return (jlong) receiver_interface;
}

/*
 * Function runOtAsReceiver : This function runs the ot extension as the sender.
 * 
 * param sigma : The input array that holds all the receiver inputs for each ot 
 * in a one dimensional array.
 * param bitLength : The length of each element
 * param output : An empty array that will be filled with the result of the ot 
 * extension in one dimensional array. That is, 
 * The relevant i'th element x1/x2 will be placed in the position bitLength*sizeof(BYTE).
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otBatch_otExtension_OTExtensionMaliciousReceiver_runOtAsReceiver(
JNIEnv *env, jobject, jlong receiver, jbyteArray sigma, jint numOfOts, 
jint bitLength, jbyteArray output, jstring version) {

    if (0 == receiver) {
	return;
    }

    //cout << "Started runOtAsReceiver." << endl;

    // The masking function with which the values that are sent 
    // in the last communication step are processed
    // Choose OT extension version: G_OT, C_OT or R_OT
    BYTE ver;
  
    // get ot version from java
    const char* str = env->GetStringUTFChars(version, NULL);

    // (supports all of the SHA hashes. 
    // Get the name of the required hash and instantiate that hash.)
    if(strcmp (str,"general") == 0) {
	ver = G_OT;
    } else if(strcmp (str,"correlated") == 0) {
	ver = C_OT;
    } else if(strcmp (str,"random") == 0) {
	ver = R_OT;
    }
  
    //if(ver == C_OT) {
    MaskingFunction * masking_function = new XORMasking(bitLength);
    //}

    jbyte *sigmaArr = env->GetByteArrayElements(sigma, 0);
	
    CBitVector choices, response;
    choices.Create(numOfOts);
  
    //Pre-generate the response vector for the results
    response.Create(numOfOts, bitLength);

    //copy the sigma values received from java
    for(int i=0; i<numOfOts;i++){
	choices.SetBit((i/8)*8 + 7-(i%8), sigmaArr[i]);
    }

    //run the ot extension as the receiver
    OtExtensionMaliciousReceiverInterface * receiver_interface = (OtExtensionMaliciousReceiverInterface *) receiver;

   // cout << "started receiver_interface->obliviously_receive()" << endl;
    receiver_interface->obliviously_receive(choices, response, numOfOts, bitLength, ver, masking_function);
    //cout << "ended receiver_interface->obliviously_receive()" << endl;

    //prepare the out array
    jbyte *out = env->GetByteArrayElements(output, 0);
    int sizeResponseInBytes = numOfOts*bitLength/8;
    for(int i = 0; i < sizeResponseInBytes; i++) {
	//copy each byte result to out
	out[i] = response.GetByte(i);
    }

    //make sure to release the memory created in c++. The JVM will not release it automatically.
    env->ReleaseByteArrayElements(sigma,sigmaArr,0);
    env->ReleaseByteArrayElements(output,out,0);

    //free the pointer of choises and reponse
    choices.delCBitVector();
    response.delCBitVector();

    if(ver == C_OT){
	delete masking_function;
    }

    //cout << "ended runOtAsReceiver." << endl;
}

/*
 * Function deleteReceiver : deletes the receiver object
 * param receiver: a pointer to the receiver object.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otBatch_otExtension_OTExtensionMaliciousReceiver_deleteReceiver(
JNIEnv *env, jobject, jlong receiver) {
    if (0 == receiver) {
	return;
    }
    delete (OtExtensionMaliciousReceiverInterface*) receiver;
}
