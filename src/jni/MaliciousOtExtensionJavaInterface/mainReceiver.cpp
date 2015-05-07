#include "OTExtensionMaliciousReceiver.h"
#include "OTExtensionMaliciousReceiverInterface.h"
#include <jni.h>
#include <iostream>

#include <stdio.h>      /* printf, scanf, puts, NULL */
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */


using namespace maliciousot;
using std::cerr;
using std::endl;

int main(int argc, char** argv) {
    // init phase
    int baseOts = 190;
    int numOts = 700;
    int bitLength = 128;
    srand (time(NULL));
    
    OtExtensionMaliciousReceiverInterface * receiver_interface;
    receiver_interface = new OtExtensionMaliciousReceiverInterface("127.0.0.1",
								   7766, // port
								   1, // threads
								   baseOts, // base ots
								   numOts); // total ots

    receiver_interface->init_ot_receiver();
    cerr << "finished initOtReceiver." << endl;
    cerr << "Started runOtAsSender." << endl;
    
    MaskingFunction * masking_function = new XORMasking(bitLength);
    
    CBitVector choices, response;
    choices.Create(numOts);
  
    //Pre-generate the response vector for the results
    response.Create(numOts, bitLength);

    //copy the sigma values received from java
    for(int i=0; i<numOts;i++){
	choices.SetBit((i/8)*8 + 7-(i%8), rand() % 2);
    }

    //run the ot extension as the receiver
    cerr << "started receiver_interface->obliviously_receive()" << endl;
    receiver_interface->obliviously_receive(choices, response, numOts, bitLength, G_OT, masking_function);
    cerr << "ended receiver_interface->obliviously_receive()" << endl;

    //prepare the out array
    cerr << "response bitvector:" << endl;
    response.PrintHex();
    
    choices.delCBitVector();
    response.delCBitVector();

    delete masking_function;
    cerr << "ended runOtAsReceiver." << endl;
    delete receiver_interface;
}
