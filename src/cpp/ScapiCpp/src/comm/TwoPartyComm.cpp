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
}

void NativeChannel::connect() {
	Logger::log("Channel (" + me.to_log_string() + ") - connecting to peer (" + other.to_log_string() + ")");
	tcp::resolver resolver(io_service_client_);
	tcp::resolver::query query(other.getIpAddress().to_string(), to_string(other.getPort()));
	tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
	boost::asio::async_connect(clientSocket, endpoint_iterator,
		boost::bind(&NativeChannel::handle_connect, this,
			boost::asio::placeholders::error));
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
	Logger::log("Channel (" + me.to_log_string() + ") - writing message. size of message: " + to_string(msg.body_length()));
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
	auto v = new vector<byte>();
	copy_byte_array_to_byte_vector((byte *)read_msg_.body(), read_msg_.body_length(), *v, 0);
	read_msgs_.push_back(v);
	size_t len = read_msg_.body_length();
	//string s(reinterpret_cast<char const*>(read_msg_.body()), len);
	//cout << "got message. size: " << len << endl;
}

vector<byte> * NativeChannel::read_one() {
	if (!read_msgs_.empty())
	{
		vector<byte>* v = read_msgs_.front();
		read_msgs_.pop_front();
		return v;
	}
	return NULL;
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