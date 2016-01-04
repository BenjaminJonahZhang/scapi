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

void NativeChannel::start_listening()
{
	Logger::log("Channel (" + me.to_log_string() + ") - starting to listen");
	boost::asio::async_read(serverSocket,
		boost::asio::buffer(read_msg_.data(), Message::header_length),
		boost::bind(&NativeChannel::handle_read_header, this,
			boost::asio::placeholders::error));
	boost::asio::ip::tcp::no_delay option(true);
	boost::asio::socket_base::do_not_route option2(true);
	serverSocket.set_option(option);
	serverSocket.set_option(option2);
}

void NativeChannel::connect() {
	Logger::log("Channel (" + me.to_log_string() + ") - connecting to peer (" + other.to_log_string() + ")");
	tcp::resolver resolver(io_service_client_);
	tcp::resolver::query query(other.getIpAddress().to_string(), to_string(other.getPort()));
	tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
	boost::asio::async_connect(clientSocket, endpoint_iterator,
		boost::bind(&NativeChannel::handle_connect, this,
			boost::asio::placeholders::error));
	boost::asio::ip::tcp::no_delay option(true);
	boost::asio::socket_base::do_not_route option2(true);
	clientSocket.set_option(option);
	clientSocket.set_option(option2);
}

void NativeChannel::handle_connect(const boost::system::error_code& error)
{
	if (!error)
	{
		Logger::log("Channel (" + me.to_log_string() + ") - succesfully connected to peer (" + other.to_log_string() + ")");
		m_IsConnected = true;
	}
	else
		Logger::log("Channel (" + me.to_log_string() + ") - failed to connect to peer (" + other.to_log_string() + ")!!");
}

void NativeChannel::write(const Message& msg)
{
	io_service_client_.post(boost::bind(&NativeChannel::do_write, this, msg));
}

void NativeChannel::close()
{
	Logger::log("Channel (" + me.to_log_string() + ") - closing");
	io_service_client_.post(boost::bind(&NativeChannel::do_close, this));
}

void NativeChannel::do_write(Message msg)
{
	bool write_in_progress = !write_msgs_.empty();
	write_msgs_.push_back(msg);
	if (!write_in_progress)
	{
		boost::asio::async_write(clientSocket,
			boost::asio::buffer(write_msgs_.front().data(),
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
			boost::asio::async_write(clientSocket,
				boost::asio::buffer(write_msgs_.front().data(),
					write_msgs_.front().length()),
				boost::bind(&NativeChannel::handle_write, this,
					boost::asio::placeholders::error));
		}
		Logger::log("Channel( " + me.to_log_string() + "): done writing.");
	}
	else
	{
		Logger::log("Channel( " + me.to_log_string() + "error when writing message: " + error.message());
		m_IsConnected = false;
		do_close();
	}
}

void NativeChannel::handle_read_header(const boost::system::error_code& error)
{
	if (!error && read_msg_.decode_header())
	{
		boost::asio::async_read(serverSocket,
			boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
			boost::bind(&NativeChannel::handle_read_body, this,
				boost::asio::placeholders::error));
	}
	else
	{
		Logger::log("Channel( " + me.to_log_string() + "error when reading message header: " + error.message());
		m_IsConnected = false;
		do_close();
	}
}

void NativeChannel::handle_read_body(const boost::system::error_code& error)
{
	if (!error)
	{
		handle_msg(read_msg_);
		boost::asio::async_read(serverSocket,
			boost::asio::buffer(read_msg_.data(), Message::header_length),
			boost::bind(&NativeChannel::handle_read_header, this,
				boost::asio::placeholders::error));
	}
	else
	{
		Logger::log("Channel( " + me.to_log_string() + "error when reading message body: " + error.message());
		m_IsConnected = false;
		do_close();
	}
}

void NativeChannel::handle_msg(const Message& msg) {
	int m_len = read_msg_.body_length();
	auto v = new vector<byte>(m_len);
	memcpy(&(v->at(0)), read_msg_.body(), m_len);
	std::unique_lock<std::mutex> lk(m);
	read_msgs_.push_back(v);
	lk.unlock();
	cv.notify_one();
}

vector<byte> * NativeChannel::read_one() {
	// Wait until main() sends data
	std::unique_lock<std::mutex> lk(m);
	while (read_msgs_.empty())
		cv.wait(lk);

	auto item = read_msgs_.front();
	read_msgs_.pop_front();
	return item;
}

/*****************************************/
/* ChannelServer						 */
/*****************************************/

void ChannelServer::write(byte* data, int size) {
	msg.body_length(size);
	memcpy(msg.body(), &data[0], msg.body_length());
	msg.encode_header();
	channel->write(msg);
}