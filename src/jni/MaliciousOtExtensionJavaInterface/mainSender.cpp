#include "OTExtensionMaliciousSender.h"
#include "OTExtensionMaliciousSenderInterface.h"
#include <jni.h>
#include <stdio.h>      /* printf, scanf, puts, NULL */
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

using namespace maliciousot;

int main(int argc, char** argv) {
    // init phase
    int baseOts = 190;
    int numOts = 700;
    int bitLength = 128;
    srand (time(NULL));
    
    OtExtensionMaliciousSenderInterface * sender_interface;
    sender_interface = new OtExtensionMaliciousSenderInterface("127.0.0.1",
							       7766, // port
							       1, // threads
							       baseOts, // base ots
							       numOts); // total ots
    sender_interface->init_ot_sender();
    cerr << "finished initOtSender." << endl;
    
    // run ot as sender phase
    CBitVector delta, X1, X2;
    MaskingFunction * masking_function = new XORMasking(bitLength);
    
    //Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values
    X1.Create(numOts, bitLength);
    X2.Create(numOts, bitLength);
    for(int i = 0; i < numOts * bitLength/8; i++) {
	X1.SetByte(i, rand() % 2);
	X2.SetByte(i, rand() % 2);
    }

    cerr << "started receiver_interface->obliviously_send()" << endl;
    sender_interface->obliviously_send(X1, X2, numOts, bitLength, G_OT, masking_function); //, delta);
    cerr << "ended receiver_interface->obliviously_send()" << endl;
    X1.delCBitVector();
    X2.delCBitVector();
    delta.delCBitVector();

    cerr << "ended runOtAsSender." << endl;

    delete sender_interface;
}
