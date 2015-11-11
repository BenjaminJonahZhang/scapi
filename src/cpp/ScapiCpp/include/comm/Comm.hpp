#pragma once

#include "../primitives/Common.hpp"
#include <boost/asio/ip/address.hpp>

using ipaddress = boost::asio::ip::address;     // Reduce the typing a bit later...

/**
* Class to use in the send and receive functions.
*/
class Message{
private:
	byte* data = NULL;
	int len = 0;
public:
	Message(byte* data, int len) { this->data = data; this->len = len; };
	void setData(byte* data, int len) { this->data = data; this->len = len; };
	pair<byte*, int> getData() { return pair<byte*, int>(data, len); };
};

/**
* Represents a connection between two parties. Once a channel is open and the connection is established it can be used to send and receive messages over it.
* There are different types of channels and we use the Decorator Design Pattern to implement some of them.
*/
class Channel {
public:
	virtual void send(string data) =0;
	virtual string receive() = 0;
	virtual void close() = 0;
	virtual bool isClosed()=0;
};

/*
* Abstract class that holds data and functionality common to different types of concrete channels.
*/
class PlainChannel : public Channel {
public:
	static enum State {
		NOT_INIT,
		CONNECTING,
		SECURING,
		READY
	};

private:
	State state;

public:
	PlainChannel() { state = State::NOT_INIT; };
	/**
	* returns the state of the channel. This class that implements the channel interface has a private attribute state. Other classes
	* that implement channel (and the decorator abstract class) need to pass the request thru their channel private attribute.
	*/
	State getState() { return state; };
	/**
	* Sets the state of the channel. This class that implements the channel interface has a private attribute state. Other classes
	* that implement channel (and the decorator abstract class) need to pass the request thru their channel private attribute.
	*/
	void setState(State state) { this->state = state; };
	virtual bool connect() =0;
	virtual bool isConnected()=0;
};