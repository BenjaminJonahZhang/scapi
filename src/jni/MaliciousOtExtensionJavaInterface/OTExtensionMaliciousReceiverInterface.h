#ifndef _OTEXT_MALICIOUS_RECEIVER_INTERFACE_H_
#define _OTEXT_MALICIOUS_RECEIVER_INTERFACE_H_

#include <MaliciousOTExtension/util/typedefs.h>
#include <MaliciousOTExtension/util/socket.h>
#include <MaliciousOTExtension/util/cbitvector.h>
#include <MaliciousOTExtension/ot/ot-extension-malicious.h>
#include <MaliciousOTExtension/ot/xormasking.h>
#include <MaliciousOTExtension/ot/pvwddh.h>

#include <vector>
#include <time.h>

#include <limits.h>
#include <iomanip>
#include <string>

#include "OtExtensionMaliciousCommonInterface.h"

namespace maliciousot {

/*
 * this class is the gateway class to the ot extension malicious library.
 * the original code used global variables and manipulated them via global functions,
 * which is a big NO-NO in terms of code readability and safety.
 *
 * since the code is not commented i will make a few assumptions but the interface
 * code may be changed in the future to reflect the author's original intentions.
 */
class OtExtensionMaliciousReceiverInterface : public OtExtensionMaliciousCommonInterface {
 public:
    OtExtensionMaliciousReceiverInterface(const char* address, int port, int num_of_threads, 
					  int num_base_ots, int num_ots);
    virtual ~OtExtensionMaliciousReceiverInterface();
    void init_ot_receiver();
    BOOL precompute_base_ots_receiver();
    BOOL obliviously_receive(CBitVector& choices, CBitVector& ret,
			     int numOTs, int bitlength, BYTE version,
			     MaskingFunction * masking_function);
};

}

#endif //_OTEXT_MALICIOUS_RECEIVER_INTERFACE_H_
