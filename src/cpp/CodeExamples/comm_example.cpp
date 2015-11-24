#include <boost/thread/thread.hpp>
#include "../ScapiCpp/include/comm/TwoPartyComm.hpp"

int main(int argc, char* argv[])
{
	try
	{
		//if (argc != 3)
		//{
		//	std::cerr << "Usage: chat_client <host> <port>\n";
		//	return 1;
		//}

		boost::asio::io_service io_service_in;
		boost::asio::io_service io_service_out;
		SocketPartyData sp1(IpAdress::from_string("127.0.0.1"), 3000);
		SocketPartyData sp2(IpAdress::from_string("127.0.0.1"), 5201);
		if (sp1 == sp2)
			cout << "equal! wrong!" << endl;
		//NativeChannel c(&sp1, &sp2, io_service_in, io_service_out);

	//	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service_in));
	//	boost::thread t2(boost::bind(&boost::asio::io_service::run, &io_service_out));

	//	char line[Message::max_body_length + 1];
	//	while (std::cin.getline(line, Message::max_body_length + 1))
	//	{
	//		using namespace std; // For strlen and memcpy.
	//		Message msg;
	//		msg.body_length(strlen(line));
	//		memcpy(msg.body(), line, msg.body_length());
	//		msg.encode_header();
	//		c.send(msg);
	//	}

	//	c.close();
	//	t.join();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}