#include "CommunicationSetup.h"
#include <string.h>
#include <iostream>
#include <MaliciousOTExtension/util/socket.h>

using namespace std;
using namespace maliciousot;

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeChannel_initSendSocket
  (JNIEnv *env, jobject, jstring ip, jint port){

	 const char* ipS = env->GetStringUTFChars(ip, 0);
	
	 CSocket* s = new CSocket();
	 s->Socket();
	 
	 bool connect = s->Connect(ipS, port);
	 
	 env->ReleaseStringUTFChars(ip, ipS);

	 if (connect){
		 s->DisableNagle();
		 return (long) s;
	 } else{ 
		 return 0;
		 delete s;
	 }

}

JNIEXPORT void JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeChannel_send
  (JNIEnv *env, jobject, jlong sendSocketPtr, jbyteArray data){
	  
	  jbyte* msg = env->GetByteArrayElements(data, 0);

	  int size = env->GetArrayLength(data);
	  ((CSocket*)sendSocketPtr)->Send(&size, sizeof(int));
	  
	  ((CSocket*)sendSocketPtr)->Send((char*)msg, size);

	  env->ReleaseByteArrayElements(data, msg, 0);
}


JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeChannel_receive
  (JNIEnv *env, jobject, jlong receiveSocketPtr){
	  
	  int size;
	  ((CSocket*)receiveSocketPtr)->Receive((BYTE*) &size, sizeof(int));
	   
	  char* buf = new char[size];
	  ((CSocket*)receiveSocketPtr)->Receive(buf, size*sizeof(char));

	 jbyteArray received = env->NewByteArray(size);
	  env->SetByteArrayRegion(received, 0, size, (jbyte*)buf);

	  delete buf;

	  return received;

}

JNIEXPORT void JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeChannel_closeSockets
  (JNIEnv *, jobject, jlong sendSocketPtr, jlong receiveSocketPtr){
	  ((CSocket*)sendSocketPtr)->Close();
	  ((CSocket*)receiveSocketPtr)->Close();

	  delete (CSocket*)sendSocketPtr;
	  delete (CSocket*)receiveSocketPtr;
}

//JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeChannel_enableNagle
 // (JNIEnv *, jobject, jlong sendSocketPtr, jlong receiveSocketPtr){
	//  SOCKET send = (SOCKET) sendSocketPtr;
	//  SOCKET receive = (SOCKET) receiveSocketPtr;

	 //Enable Nagle algorithm.

//BOOL bOptVal = true;
//	int bOptLen = sizeof(BOOL);
//	setsockopt(send, IPPROTO_TCP, , (char*)&bOptVal, bOptLen);
	//setsockopt(receive, IPPROTO_TCP, , (char*)&bOptVal, bOptLen);

//}

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeSocketListenerThread_initReceiveSocket
  (JNIEnv *env, jobject, jstring ip, jint port){
	  const char* ipS = env->GetStringUTFChars(ip, 0);
	  
	  CSocket* serverSocket = new CSocket();
	 
	  // try to bind() and then listen
	  if ((!serverSocket->Socket()) || (!serverSocket->Bind(port, ipS))){ 
		  delete serverSocket;
		  return 0;
	  }
    
	  env->ReleaseStringUTFChars(ip, ipS);

	  return (long) serverSocket;
	

}

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeSocketListenerThread_accept
  (JNIEnv *, jobject, jlong serverSocketPtr){
	  if (!((CSocket*)serverSocketPtr)->Listen()) {
		  
		return 0;
	  }
    
	  CSocket* sock = new CSocket();
	  
	  if(!((CSocket*)serverSocketPtr)->Accept(*sock)) {
		  delete sock;
	      return 0;
	  }

	  sock->DisableNagle();
	  return (long) sock;	  
	
}


JNIEXPORT void JNICALL Java_edu_biu_scapi_comm_twoPartyComm_NativeSocketListenerThread_close
  (JNIEnv *, jobject, jlong serverSocketPtr){
	  ((CSocket*)serverSocketPtr)->Close();
	  delete (CSocket*)serverSocketPtr;
}
