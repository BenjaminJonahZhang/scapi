#pragma once

#include "Comm.hpp"
#include <boost/asio.hpp>
#include <map>


namespace boost_ip = boost::asio::ip; // reduce the typing a bit later...
using IpAdress = boost_ip::address;

/**
* A marker interface. Each type of party should have a concrete class that implement this interface.
*/
class PartyData{};

/**
* This class holds the data of a party in a communication layer.
* It should be used in case the user wants to use the regular mechanism of communication using tcp sockets.
*/
class SocketPartyData : public PartyData {
private:
	IpAdress ipAddress; // party's address.
	int port; // port number to listen on.
	int compare(const SocketPartyData &other) const;
public:
	/**
	* Constructor that sets the given arguments.
	* @param ip Party's address.
	* @param port Port number to listen on.
	*/
	SocketPartyData(IpAdress ip, int port) {
		ipAddress = ip;
		this->port = port;
	};
	IpAdress getIpAddress() { return ipAddress; };
	int getPort() { return port; };
	/**
	* Compares two parties.
	*<0 if this party's string is smaller than the otherParty's string representation.
	*>0 if this party's string is larger than the otherParty's string representation.
	*/
	bool operator==(const SocketPartyData &other) const { return (compare(other) == 0); };
	bool operator!=(const SocketPartyData &other) const { return (compare(other) != 0); };
	bool operator<=(const SocketPartyData &other) const { return (compare(other) <= 0); };
	bool operator>=(const SocketPartyData &other) const { return (compare(other) >= 0); };
	bool operator>(const SocketPartyData &other) const { return (compare(other) > 0); };
	bool operator<(const SocketPartyData &other) const { return (compare(other) < 0); };
};

class NativeChannel : public Channel {
private:
	SocketPartyData * me;
	SocketPartyData * other;
	boost::asio::ip::tcp::socket* sendSocketPtr;
	boost::asio::ip::tcp::socket* receiveSocketPtr;
	bool _isClosed;

public:
	NativeChannel(SocketPartyData *me, SocketPartyData *other) {
		this->me = me;
		this->other = other;
		sendSocketPtr = NULL;
		receiveSocketPtr = NULL;
	}
	bool connect() override;
	void send(Message message) override;
	Message receive() override;
	void close() override;
	bool isClosed() override;
	/**
	* This function sets the channel state to READY in case both send and receive sockets are connected.
	*/
	void setReady();
	/**
	* Returns if the send socket is connected.
	*/
	bool isSendConnected() { return (sendSocketPtr != NULL); };
	void setReceiveSocket(long receiveSocket);
	void enableNagle();
};

class NativeSocketListenerThread {
private:
	SocketPartyData *me;
	void * serverSocket;
public:
	vector<NativeChannel *> channels; // all connections between me and the other party. The received sockets of each channel should be set when accepted. 
	bool bStopped = false; // a flag that indicates if to keep on listening or stop.

	/**
	* Opens the server socket.
	*/
	NativeSocketListenerThread(vector<NativeChannel *> & channels, SocketPartyData *me);
	void stopConnecting() { bStopped = true; };
	void run();
};

class TwoPartyCommunicationSetup;
class Watchdog {
public:
	Watchdog(long timeout);
	void addTimeoutObserver(TwoPartyCommunicationSetup * tpcs);
	void start();
	void stop();
};

/**
* The TwoPartyCommunicationSetup interface manages the common functionality of all two party communications.
* There are several ways to communicate between two parties - using sockets, queues, etc. Each concrete way should implements this
* interface and the functions in it.<p>
* This interface should be used in the specific case of communication between two parties, while CommunicationSetup should be used in
* the extended case of multi-party communication.<p>
*
* The Communications Layer package is a tool used by a client that is interested in setting up connections
* between itself and other party. As such, this layer does not initiate any independent tasks, but the opposite. Given two parties,
* it attempts to set connections to them according to parameters given by the calling application. If succeeds, it returns these
* connections so that the calling client can send and receive data over them.<p>
* Note that multiple connections can be created although it is a two party communication; the user can ask to set any number of connections.
*
* An application written for running a two party protocol can be the client of the Communications Layer. An example of a possible
* usage follows:<p>
* <ul>
* <li>Instantiate an object of type TwoPartyCommunicationSetup.</li>
* <li>Call the prepareForCommunication method of that object with two parties to connect to and other setup parameters.</li>
* <li>Get from prepareForCommunication a container holding all ready connections.</li>
* <li>Start the two party protocol.</li>
* <li>Call the send and receive methods of the ready connections as needed by the protocol.</li>
* </ul>
* The application may be interested in putting each connection in a different thread but it is up to the application to do so and not
* the responsibility of the Communications Layer. This provides more flexibility of use.
*
* CommunicationSetup implements the TimeoutObserver interface.
* This interface supplies a mechanism for notifying classes that a timeout has arrived.
*/
class TwoPartyCommunicationSetup {

public:
	/**
	* An application that wants to use the communication layer will call this function in order to prepare for
	* communication after providing the required parameters. <p>
	* The constructor of the concrete classes should receive the data of the two parties participate in the communication.
	* After that, this function initiates the creation of the final actual connections between the parties. <p>
	* Each connection has a unique name, that we call ID. This name used to distinguish between the created connections
	* in order to make it easier and more convenient to understand what is the usage of each connection.<p>
	* If this function succeeds, the application may use the send and receive functions of the created channels to
	* pass messages.<p>
	* In this function, Nagle's algorithm is disabled; for cryptographic protocols this is typically much better.
	* In order to use the Nagle algorithm, call the enableNagle() function.
	*
	* @param connectionsIds Each required connection's name.
	* @param timeOut the maximum amount of time we allow for the connection stage.
	* @return a map contains the connected channels. The key to the map is the id of the connection.
	* @throws TimeoutException in case a timeout has occurred before all channels have been connected.
	*/
	virtual map<string, Channel *> * prepareForCommunication(vector<string> & connectionsIds, long timeOut) = 0;

	/**
	* An application that wants to use the communication layer will call this function in order to prepare for
	* communication after providing the required parameters. <p>
	* The constructor of the concrete classes should receive the data of the two parties participate in the communication.
	* After that, this function initiates the creation of the final actual connections between the parties. <p>
	* Each connection has a unique name, that we call ID. This name used to distinguish between the created connections
	* in order to make it easier and more convenient to understand what is the usage of each connection.
	* In this function, the names of the connections are chosen by default, meaning the connections are numbered
	* according to their index. i.e the first connection's name is "1", the second is "2" and so on.<p>
	* If this function succeeds, the application may use the send and receive functions of the created channels to
	* pass messages.<p>
	* In this function, Nagle's algorithm is disabled; for cryptographic protocols this is typically much better.
	* In order to use the Nagle algorithm, call the enableNagle() function.
	*
	* @param connectionsNum The number of requested connections.
	* @param timeOut the maximum amount of time we allow for the connection stage.
	* @return a map contains the connected channels. The key to the map is the id of the connection.
	* @throws TimeoutException in case a timeout has occurred before all channels have been connected.
	*/
	virtual map<string, Channel *> * prepareForCommunication(int connectionsNum, long timeOut)=0;

	/**
	* Enables to use Nagle algorithm in the communication. <p>
	* By default Nagle algorithm is disabled since it is much better for cryptographic algorithms.
	*
	*/
	virtual void enableNagle() = 0;

	/**
	* There are several implementations that should close the communication object.
	*/
	virtual void close()=0;

	/**
	* Derived class should implement to handle timeout occurances. 
	*/
	virtual void timeoutOccured(Watchdog arg0) = 0;
};

class NativeSocketCommunicationSetup : public TwoPartyCommunicationSetup {
private:
	map<string, Channel *> * connectionsMap;
	/**
	* This function does the actual creation of the communication between the parties.<p>
	* A connected channel between two parties has two sockets. One is used by P1 to send messages and p2 receives them,
	* while the other used by P2 to send messages and P1 receives them.
	*
	* The function does the following steps:
	* 1. Calls the connector.createChannels function that creates a channel for each connection.
	* 2. Start a listening thread that accepts calls from the other party.
	* 3. Calls the connector.connect function that calls each channel's connect function in order to connect each channel to the other party.
	* @param connectionsIds The names of the requested connections.
	*/
	void establishConnections(vector<string>& connectionsIds);
	vector<NativeChannel *> createChannels(vector<string> & connectionsIds, bool checkIdentity);
	void connect(vector<NativeChannel *> channels);
	void verifyConnectingStatus();
	bool areAllConnected();

public:
	bool bTimedOut = false; // indicates whether or not to end the communication.
	Watchdog watchdog; // used to measure times.
	bool enableNagle_ = false; // indicates whether or not to use Nagle optimization algorithm.
	NativeSocketListenerThread listeningThread; // listen to calls from the other party.
	int connectionsNumber; // holds the number of created connections. 
	SocketPartyData* me;	 // the data of the current application.
	SocketPartyData* other; // the data of the other application to communicate with.

	/**
	* A constructor that set the given parties.
	* @param me The data of the current application.
	* @param party The data of the other application to communicate with.
	* @throws DuplicatePartyException
	*/
	NativeSocketCommunicationSetup(SocketPartyData * me, SocketPartyData* party);
	map<string, Channel *> * prepareForCommunication(vector<string> & connectionsIds, long timeOut) override;
	map<string, Channel *> * prepareForCommunication(int connectionsNum, long timeOut) override;
	void createListener(vector<NativeChannel *> channels);
	void enableNagle() override {
		//Set to true the boolean indicates whether or not to use the Nagle optimization algorithm. 
		//For Cryptographic algorithms is better to have it disabled.
		this->enableNagle_ = true;
	};
	void timeoutOccured(Watchdog w) override;

	/**
	* Sets the flag bStopped to false. In the run function of this thread this flag is checked -
	* if the flag is true the run functions returns, otherwise continues.
	*/
	void stopConnecting();
	void close() override {};
	void enableNagleInChannels();
};