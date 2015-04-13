#ifndef _OTEXT_CONNECTION_MANAGER_H_
#define _OTEXT_CONNECTION_MANAGER_H_

#include <MaliciousOTExtension/util/typedefs.h>
#include <MaliciousOTExtension/util/socket.h>

#include <limits.h>
#include <iomanip>
#include <vector>
#include <time.h>

namespace maliciousot {

// abstract base class
class ConnectionManager {

 public:
    static const char * DEFAULT_ADDRESS;
    static const USHORT DEFAULT_PORT = 7766;

    // ctors
    //ConnectionManager(int role, int num_of_threads, const char * address, int port);
    explicit ConnectionManager(int role, int num_of_threads = 1,  // num of threads
								   const char * address = DEFAULT_ADDRESS, // address
								   int port = DEFAULT_PORT);

    // dtor
    virtual ~ConnectionManager();
    
    inline CSocket * get_sockets_data() { //return m_sockets.data(); 
	return m_sockets;};
    inline CSocket& get_socket(int i) { return m_sockets[i]; };
    inline int get_num_of_threads() { return m_num_of_threads; };
    virtual BOOL setup_connection() = 0;
    
 protected:
    int m_num_of_threads;
    const char* m_address;
    USHORT m_port;
    int m_pid; // thread id - indicates the role: (0 for server, 1 for client)
    //std::vector<CSocket> m_sockets;
	CSocket* m_sockets;
};

// server class (used by sender)
class ConnectionManagerServer : public ConnectionManager {
 public:
	 ~ConnectionManagerServer();
    ConnectionManagerServer(int role, int num_of_threads, const char * address, int port);
    explicit ConnectionManagerServer(int role);
    virtual BOOL setup_connection();

};

// client class (used by receiver)
class ConnectionManagerClient : public ConnectionManager {
 public:
	 ~ConnectionManagerClient();
    ConnectionManagerClient(int role, int num_of_threads, const char * address, int port);
    explicit ConnectionManagerClient(int role);
    virtual BOOL setup_connection();
};

} // end of namespace

#endif //_OTEXT_CONNECTION_MANAGER_H_
