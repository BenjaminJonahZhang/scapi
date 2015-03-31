#ifndef _OTEXT_MALICIOUS_COMMON_INTERFACE_H_
#define _OTEXT_MALICIOUS_COMMON_INTERFACE_H_

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

#include "ConnectionManager.h"

namespace maliciousot {

/*
 * this class is the gateway class to the ot extension malicious library.
 * the original code used global variables and manipulated them via global functions,
 * which is a big NO-NO in terms of code readability and safety.
 *
 * since the code is not commented i will make a few assumptions but the interface
 * code may be changed in the future to reflect the author's original intentions.
 */
class OtExtensionMaliciousCommonInterface {

 public:
    static const char* m_initial_seed;

    OtExtensionMaliciousCommonInterface(int role, int num_base_ots, int num_ots);
    virtual ~OtExtensionMaliciousCommonInterface();

 protected:
    void init_seeds(int role);

    // handles the networking stuff
    ConnectionManager * m_connection_manager;

    // handles the malicious ot protocol 
    // (each party runs both a sender and a receiver since 
    // there are 2 ots running: the base ot and the extension ot).
    Mal_OTExtensionSender * m_sender;
    Mal_OTExtensionReceiver * m_receiver;

    // Naor-Pinkas OT protocol
    BaseOT * m_baseot_handler;

    // settings of ot protocol
    int m_num_base_ots;
    int m_num_ots;
    int m_counter;
    int m_num_checks;
    SECLVL m_security_level;
    
    // seeds (SHA PRG)
    BYTE m_receiver_seed[SHA1_BYTES];
    BYTE m_sender_seed[AES_BYTES];
    
    // implementation details
    CBitVector U;
    BYTE *m_sender_key_seeds;
    BYTE *m_receiver_key_seeds_matrix;
    
    // logger stuff
    double logger_random_gentime;
};

}

#endif //_OTEXT_MALICIOUS_COMMON_INTERFACE_H_
