#pragma once

#include "Comm.hpp"

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