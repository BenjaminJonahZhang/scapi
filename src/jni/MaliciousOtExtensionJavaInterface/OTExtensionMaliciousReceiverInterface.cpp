#include "OTExtensionMaliciousReceiverInterface.h"

maliciousot::OtExtensionMaliciousReceiverInterface::OtExtensionMaliciousReceiverInterface(const char* address, 
									     int port,
									     int num_of_threads,
									     int num_base_ots, 
									     int num_ots) : 
    OtExtensionMaliciousCommonInterface(1,
					num_base_ots, 
					num_ots) {
    m_connection_manager = new ConnectionManagerClient(1, num_of_threads, address, port);
}

void maliciousot::OtExtensionMaliciousReceiverInterface::init_ot_receiver() {
    int nSndVals = 2;
    int wdsize = 1 << (CEIL_LOG2(m_num_base_ots));
    int nblocks = CEIL_DIVIDE(m_num_ots, NUMOTBLOCKS * wdsize);
    int s2ots = nblocks * m_num_base_ots;
    
    m_sender_key_seeds = (BYTE*) malloc(AES_KEY_BYTES * m_num_base_ots);//m_security_level.symbits);
    m_receiver_key_seeds_matrix = (BYTE*) malloc(AES_KEY_BYTES * 2 * s2ots);

    // client connect
    m_connection_manager->setup_connection();

    // 1st step: pre-compute the PVW base OTs
    precompute_base_ots_receiver();

    assert(nblocks <= NUMOTBLOCKS);

    // 2nd step: OT extension step to obtain the base-OTs for the next step
    m_sender = new Mal_OTExtensionSender(nSndVals, m_security_level.symbits,
					 m_connection_manager->get_sockets_data(),
					 U, m_sender_key_seeds, m_num_base_ots,
					 m_num_checks, s2ots, m_sender_seed);
    
    CBitVector seedA(s2ots * AES_KEY_BITS);
    CBitVector seedB(s2ots * AES_KEY_BITS);

    XORMasking* masking_function = new XORMasking(AES_KEY_BITS);
    m_sender->send(s2ots, AES_KEY_BITS, seedA, seedB, R_OT, 1, masking_function);
    delete masking_function;

    for(int i = 0; i < s2ots; i++) {
	memcpy(m_receiver_key_seeds_matrix + 2 * i * AES_KEY_BYTES, 
	       seedA.GetArr() + i * AES_KEY_BYTES, 
	       AES_KEY_BYTES);
	
	memcpy(m_receiver_key_seeds_matrix + (2*i+1) * AES_KEY_BYTES, 
	       seedB.GetArr() + i * AES_KEY_BYTES, 
	       AES_KEY_BYTES);
    }
    
    m_receiver = new Mal_OTExtensionReceiver(nSndVals, m_security_level.symbits,
					     m_connection_manager->get_sockets_data(),
					     m_receiver_key_seeds_matrix, m_receiver_seed,
					     m_num_base_ots, s2ots);
}

/**
 * PrecomputeBaseOTsReceiver
 * (should be a member of a class instead of manipulating globals)
 */
BOOL maliciousot::OtExtensionMaliciousReceiverInterface::precompute_base_ots_receiver() {

  int nSndVals = 2;
  BYTE* pBuf = new BYTE[m_num_base_ots * SHA1_BYTES];
  int log_nVals = (int) ceil(log((double)nSndVals)/log((double)2));
  int cnt = 0;
	
  U.Create(m_num_base_ots * log_nVals, m_receiver_seed, cnt);
	
  m_baseot_handler->Receiver(nSndVals, m_num_base_ots, U, m_connection_manager->get_socket(0), pBuf);
	
  //Key expansion
  BYTE* pBufIdx = pBuf;
  for(int i=0; i<m_num_base_ots; i++ ) { //80 HF calls for the Naor Pinkas protocol
      memcpy(m_sender_key_seeds + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
      pBufIdx+=SHA1_BYTES;
  } 
  delete [] pBuf;

  return true;
}

/**
 * ObliviouslyReceive
 * (should be a member of a class instead of manipulating globals)
 */
BOOL maliciousot::OtExtensionMaliciousReceiverInterface::obliviously_receive(CBitVector& choices, 
									     CBitVector& ret, 
									     int numOTs, 
									     int bitlength, 
									     BYTE version,
									     MaskingFunction * masking_function) {
    bool success = FALSE;

    // Execute OT receiver routine 	
    success = m_receiver->receive(numOTs, bitlength, choices, ret, version, 
				  m_connection_manager->get_num_of_threads(), 
				  masking_function);
    
    return success;
}

maliciousot::OtExtensionMaliciousReceiverInterface::~OtExtensionMaliciousReceiverInterface() {
    delete m_connection_manager;
    delete m_sender;
    delete m_receiver;
}
