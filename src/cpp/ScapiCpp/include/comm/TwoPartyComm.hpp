#pragma once

#include "Comm.hpp"
#include <map>

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
	ipaddress ipAddress;	//Party's address.
	int port; //Port number to listen on.

public:
	/**
	* Constructor that sets the given arguments.
	* @param ip Party's address.
	* @param port Port number to listen on.
	*/
	SocketPartyData(ipaddress ip, int port) {
		this->ipAddress = ip;
		this->port = port;
	};
	ipaddress getIpAddress() { return ipAddress; };
	int getPort() { return port; };
	/**
	* Compares two parties.
	*<0 if this party's string is smaller than the otherParty's string representation.
	*>0 if this party's string is larger than the otherParty's string representation.
	*/
	bool operator==(const SocketPartyData &other) const;
	bool operator!=(const SocketPartyData &other) const;
	bool operator<=(const SocketPartyData &other) const;
	bool operator>=(const SocketPartyData &other) const;
	bool operator>(const SocketPartyData &other) const;
	bool operator<(const SocketPartyData &other) const;
};

class Watchdog {};
class SSLSocketFactory {};

/**
* This class represents a concrete channel in the Decorator Pattern used to create Channels. This channel ensures TCP
* type of communication.
* In order to enforce the right usage of the Channel class we will restrict the ability to instantiate one,
* only to classes within the Two Party Communication Layer's package. This means that the constructor of the channel will be
* unreachable from another package. However, the send, receive and close functions will be declared public, therefore
* allowing anyone holding a channel to be able to use them.
*
* The difference between this implementation to the {@link PlainTCPChannel} is that here there are two sockets:
* one used to receive messages and one used to send messages. The other {@link PlainTCPChannel} has one socket used
* both to send and receive.
*/
class PlainTCPSocketChannel : public PlainChannel {
private:
	//Socket receiveSocket;				//A socket used to receive messages.
	//ObjectInputStream inStream;			//Used to receive a message.
	Message intermediate;
	Message msgObj;
	byte* msgBytes;
	SocketPartyData me;					//Used to send the identity if needed.
public:
	//Socket sendSocket;				//A socket used to send messages.
	//ObjectOutputStream outStream;		//Used to send a message
	//InetSocketAddress socketAddress;	//The address of the other party.
	bool checkIdentity;			//Indicated if there is a need to verify identity.

	/**
	* A constructor that set the state of this channel to not ready.
	*/
	PlainTCPSocketChannel();

	/**
	* A constructor that create the socket address according to the given ip and port and set the state of this channel to not ready.
	* @param ipAddress other party's IP address.
	* @param port other party's port.
	*/
	PlainTCPSocketChannel(InetAddress ipAddress, int port, boolean checkIdentity, SocketPartyData me);

	/**
	* A constructor that set the given socket address and set the state of this channel to not ready.
	* @param socketAddress other end's InetSocketAddress
	*/
	PlainTCPSocketChannel(InetSocketAddress socketAddress, boolean checkIdentity, SocketPartyData me);

	/**
	* Sends the message to the other user of the channel with TCP protocol.
	*
	* @param msg the object to send.
	* @throws IOException Any of the usual Input/Output related exceptions.
	*/
	void send(Serializable msg);

	/**
	* Receives the message sent by the other user of the channel.
	*/
	Serializable receive();

	/**
	* Closes the sockets and all other used resources.
	*/
	void close();
	/**
	* Checks if the channel os closed or not.
	* @return true if the channel is closed; False, otherwise.
	*/
	bool isClosed();

	/**
	* Connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to
	* is not up yet then we sleep for a while and try again until the connection is established.
	* This is done by the {@link SocketCommunicationSetup} which keeps trying until it succeeds or a timeout has
	* been reached.<p>
	* After the connection has succeeded the output stream is set for the send function.
	* @throws IOException
	*/
	bool connect();
	void sendIdentity();

	/**
	* Returns if the send socket is connected.
	*/
	bool isSendConnected();
	bool isConnected() { return isSendConnected(); };

	/**
	* Sets the receive socket and the input stream.
	* @param socket the receive socket to set.
	*/
	void setReceiveSocket(Socket socket);

	/**
	* This function sets the channel state to READY in case both send and receive sockets are connected.
	*/
	void setReady();

	/**
	* Enable/disable the Nagle algorithm according to the given boolean.
	* @param enableNagle.
	*/
	void enableNage(bool enableNagle);
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
	virtual map<string, Channel *> prepareForCommunication(vector<string> & connectionsIds, long timeOut) = 0;

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
	virtual map<string, Channel *> prepareForCommunication(int connectionsNum, long timeOut)=0;

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

/**
* This class manage the socket channels in both two party and multiparty communications. <P>
* The class does the creation of the channels and the connect step during the communication setup. <p>
* Although it is declared "public" it is not for public usage and we recommend not to use it.
* In order to setup a communication use one of the communication setup classes.
*/
class TwoPartySocketConnector {
private:
	SocketPartyData * me; //The data of the current application
	SocketPartyData * other; //The data of the other application to communicate with.
	bool bStopped = false; //A flag that indicates if to keep on listening or stop.
	bool isSecure = false; // A flag that indicates to use SSL or not.
	SSLSocketFactory factory; //In case of SSL communication, the sockets are created via this factory.
	map<string, Channel *> connectionsMap;
	/**
	* @return true if all the channels are in READY state, false otherwise.
	*/
	bool areAllConnected();

public:
	/**
	* A constructor that set the parties.<p>
	* In case this constructor has been called, the created channels will be plain.
	*/
	TwoPartySocketConnector(SocketPartyData * me, SocketPartyData * party) {
		this->me = me;
		this->other = party;
		this->isSecure = false;
	};

	/**
	* A constructor that set the parties and the factory.<p>
	* In case this constructor has been called, the created channels will be secure.
	*/
	TwoPartySocketConnector(SocketPartyData * me, SocketPartyData *party, SSLSocketFactory factory) : TwoPartySocketConnector(me, party) {
		this->isSecure = true;
		this->factory = factory;
	}

	/**
	* Creates the channels and give them the names in connectionsIds array.
	* @param connectionsIds Array of channels names.
	* @param checkIdentity A flag that indicates whether or not to check that incoming connection is from the expected party.
	* @return PlainTCPSocketChannel[] Array of created channels.
	*/
	vector<PlainTCPSocketChannel *> createChannels(vector<string> & connectionsIds, bool checkIdentity); 
	/**
	* This function calls each channel to connect to the other party.
	*/
	void connect(vector<PlainTCPSocketChannel *> channels);
	/**
	* Sets the flag bStopped to false. In the run function of this thread this flag is checked -
	* if the flag is true the run functions returns, otherwise continues.
	*/
	void stopConnecting();
	/**
	* Returns the object that holds the connections.
	* @return EstablishedSocketConnections
	*/
	map<string, Channel *> getConnections() { return connectionsMap; };
	/**
	* This function serves as a barrier. It is called from the prepareForCommunication function. The idea
	* is to let all the threads finish running before proceeding.
	*/
	void verifyConnectingStatus();
	/**
	* Enables Nagle's algorithm.
	*/
	void enableNagle();
	/**
	* @return the number of created channels.
	*/
	int getConnectionsCount() { return connectionsMap.size(); };
	/**
	* Returned this object to a fresh state by removing all connections from the map and setting bStopped to false.
	*/
	void reset() { bStopped = false; };
};

/**
* This class implements a communication between two parties using TCP sockets.<p>
* Each created channel contains two sockets; one is used to send messages and one to receive messages.<p>
* This class encapsulates the stage of connecting to other parties. In actuality, the connection to other parties is
* performed in a few steps, which are not visible to the outside user.
* These steps are:<p>
* <ul>
* <li>for each requested channel,</li>
* <li>Create an actual TCP socket with the other party. This socket is used to send messages</li>
* <li>Create a server socket that listen to the other party's call. When received, the created socket is used to receive messages from the other party.</li>
* <li>run a protocol that checks if all the necessary connections were set between my party and other party.</li>
* <li>In the end return to the calling application a set of connected and ready channels to be used throughout a cryptographic protocol.</li>
* </ul>
* From this point onwards, the application can send and receive messages in each connection as required by the protocol.<p>
*/
class SocketCommunicationSetup : public TwoPartyCommunicationSetup{
private:
	Watchdog watchdog; //Used to measure times.
	bool enableNagle_ = false; //Indicated whether or not to use Nagle optimization algorithm.
	int connectionsNumber; //Holds the number of created connections. 
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
	*
	*/
	void establishConnections(vector<string> & connectionsIds);

public:
	bool bTimedOut = false; //Indicated whether or not to end the communication.
	TwoPartySocketConnector connector; //Used to create and connect the channels to the other party.
	SocketListenerThread listeningThread; //Listen to calls from the other party.
	SocketPartyData me; //The data of the current application.
	SocketPartyData other; //The data of the other application to communicate with.

	/**
	* A constructor that set the given parties.
	* @param me The data of the current application.
	* @param party The data of the other application to communicate with.
	*/
	SocketCommunicationSetup(PartyData me, PartyData party);
	map<string, Channel *> prepareForCommunication(vector<string> & connectionsIds, long timeOut) override;
	map<string, Channel *> prepareForCommunication(int connectionsNum, long timeOut) override;
	void createListener(vector<PlainTCPSocketChannel *> channels);
	void enableNagle() override {
		// Set to true the boolean indicates whether or not to use the Nagle optimization algorithm. 
		// For Cryptographic algorithms is better to have it disabled.
		this->enableNagle_= true;
	};
	void timeoutOccured(Watchdog w) override;
	void close() override {};
};
