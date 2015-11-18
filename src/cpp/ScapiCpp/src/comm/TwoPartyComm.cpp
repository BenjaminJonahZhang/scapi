#include "../../include/comm/TwoPartyComm.hpp"

/*****************************************/
/* SocketPartyData						 */
/*****************************************/
int SocketPartyData::compare(const SocketPartyData &other) const {
	string thisString = ipAddress.to_string() + ":" + to_string(port);
	string otherString = other.ipAddress.to_string() + ":" + to_string(other.port);
	return thisString.compare(otherString);
}

/*****************************************/
/* NativeChannel						 */
/*****************************************/
bool NativeChannel::connect() {

	// try to connect
	//Logging.getLogger().log(Level.INFO, "Trying to connect to " + other.getIpAddress().getHostAddress() + " on port " + other.getPort());
	int port = other->getPort();
	const char* ipS = other->getIpAddress().to_string().c_str();
	//boost::asio::ip::tcp::socket* s = new CSocket();
	//s->Socket();
	//bool connect = s->Connect(ipS, port);
	//if (connect) {
	//	s->DisableNagle();
	//	sendSocketPtr = s;
	//	setReady();
	//	//	Logging.getLogger().log(Level.INFO, "Socket connected");
	//	return true;
	//}
	//else {
	//	//	Logging.getLogger().log(Level.INFO, "Socket failed");
	//	delete s;
	//	return false;
	//}
	return true;
}

void NativeChannel::send(Message message) {
	//sendSocketPtr->Send(&message.len, sizeof(int));
	//sendSocketPtr->Send((char*)message.data, message.len);
}