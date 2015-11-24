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
	Logger::log("Trying to connect to " + other->getIpAddress().to_string() + " on port " + to_string(other->getPort()));
	int port = other->getPort();
	string ipS = other->getIpAddress().to_string();
	tcp::resolver resolver(io_service_out);
	tcp::resolver::query query(tcp::v4(), ipS, to_string(port));
	tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
	boost::asio::async_connect(sendSocket, endpoint_iterator,
		boost::bind(&NativeChannel::handle_connect, this,
			boost::asio::placeholders::error));
	return true;
}
//
//void NativeChannel::send(Message & message) {
//	bool write_in_progress = !write_msgs_.empty();
//	write_msgs_.push_back(message);
//	if (!write_in_progress)
//	{
//		boost::asio::async_write(sendSocket,
//			boost::asio::buffer(write_msgs_.front().data(),
//				write_msgs_.front().length()),
//			boost::bind(&NativeChannel::handle_write, this,
//				boost::asio::placeholders::error));
//	}
//}
//
//Message NativeChannel::receive() {
//	return Message();
//}
//
//void NativeChannel::close() {
//	
//}

void NativeChannel::setReady() {
	this->setState(Channel::State::READY);
	this->_isClosed = false;
	Logger::log("state: ready ");
}

void NativeChannel::setReceiveSocket(tcp::socket* receiveSocket) {

}

void NativeChannel::start_accept() {
	acceptor_.async_accept(receiveSocket,
		boost::bind(&NativeChannel::handle_accept, this,
			boost::asio::placeholders::error));
}

void NativeChannel::handle_accept(const boost::system::error_code& error) {
	if (!error)
	{
		boost::asio::async_read(receiveSocket,
			boost::asio::buffer(read_msg_.data(), Message::header_length),
			boost::bind(
				&NativeChannel::handle_read_header, this,
				boost::asio::placeholders::error));
		boost::asio::ip::tcp::no_delay option(true);
		receiveSocket.set_option(option);
	}
	start_accept();
}

void NativeChannel::handle_read_header(const boost::system::error_code& error)
{
	if (!error && read_msg_.decode_header())
	{
		boost::asio::async_read(receiveSocket,
			boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
			boost::bind(&NativeChannel::handle_read_body, this,
				boost::asio::placeholders::error));
	}
	else
	{
		close();
	}
}

void NativeChannel::handle_read_body(const boost::system::error_code& error)
{
	if (!error)
	{
		boost::asio::async_read(receiveSocket,
			boost::asio::buffer(read_msg_.data(), Message::header_length),
			boost::bind(&NativeChannel::handle_read_header, this,
				boost::asio::placeholders::error));
	}
	else
	{
		close();
	}
}


void NativeChannel::enableNagle() {

}

void NativeChannel::handle_connect(const boost::system::error_code& error)
{
	if (!error)
	{
		boost::asio::async_read(sendSocket,
			boost::asio::buffer(read_msg_.data(), Message::header_length),
			boost::bind(&NativeChannel::handle_read_header, this,
				boost::asio::placeholders::error));
		setReady();
		boost::asio::ip::tcp::no_delay option(true);
		sendSocket.set_option(option);
	}
}

void NativeChannel::do_write(Message msg)
{
	bool write_in_progress = !write_msgs_.empty();
	write_msgs_.push_back(msg);
	if (!write_in_progress)
	{
		boost::asio::async_write(sendSocket, boost::asio::buffer(write_msgs_.front().data(),
				write_msgs_.front().length()),
			boost::bind(&NativeChannel::handle_write, this,
				boost::asio::placeholders::error));
	}
}

void NativeChannel::handle_write(const boost::system::error_code& error)
{
	if (!error)
	{
		write_msgs_.pop_front();
		if (!write_msgs_.empty())
		{
			boost::asio::async_write(sendSocket,
				boost::asio::buffer(write_msgs_.front().data(),
					write_msgs_.front().length()),
				boost::bind(&NativeChannel::handle_write, this,
					boost::asio::placeholders::error));
		}
	}
	else
	{
		close();
	}
}