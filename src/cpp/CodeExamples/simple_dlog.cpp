////#include "../ScapiCpp/include/primitives/DlogOpenSSL.hpp"
////#include <boost/multiprecision/random.hpp>
////#include <iostream>
////
////int main(){
////	// initiate a discrete log group
////	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
////	DlogGroup * dlog = new OpenSSLDlogZpSafePrime(128);
////
////	// get the group generator and order
////	GroupElement * g = dlog->getGenerator();
////	biginteger q = dlog->getOrder();
////
////	// create a random exponent r
////	mt19937 gen(get_seeded_random());
////	boost::random::uniform_int_distribution<biginteger> ui(0, q - 1);
////	biginteger r = ui(gen);
////
////	// exponentiate g in r to receive a new group element
////	GroupElement * g1 = dlog->exponentiate(g, r);
////	// create a random group element
////	GroupElement * h = dlog->createRandomElement();
////	// multiply elements
////	GroupElement * gMult = dlog->multiplyGroupElements(g1, h);
////
////	cout << "genrator value is:              " << ((OpenSSLZpSafePrimeElement *)g)->getElementValue() << endl;
////	cout << "exponentiate value is:          " << r << endl;
////	cout << "exponentiation result is:       " << ((OpenSSLZpSafePrimeElement *)g1)->getElementValue() << endl;
////	cout << "random element chosen is:       " << ((OpenSSLZpSafePrimeElement *)h)->getElementValue() << endl;
////	cout << "element multplied by expresult: " << ((OpenSSLZpSafePrimeElement *)gMult)->getElementValue() << endl;
////	return 0;
////}
//
//#include <boost/asio.hpp>
//#include <boost/shared_ptr.hpp>
//#include <boost/thread.hpp>
//#include <boost/thread/mutex.hpp>
//#include <boost/bind.hpp>
//#include <iostream>
//
//boost::mutex global_stream_lock;
//
//void WorkerThread(boost::shared_ptr< boost::asio::io_service > io_service)
//{
//	global_stream_lock.lock();
//	std::cout << "[" << boost::this_thread::get_id() <<
//		"] Thread Start" << std::endl;
//	global_stream_lock.unlock();
//
//	io_service->run();
//
//	global_stream_lock.lock();
//	std::cout << "[" << boost::this_thread::get_id() <<
//		"] Thread Finish" << std::endl;
//	global_stream_lock.unlock();
//}
//
//int main2(int argc, char * argv[])
//{
//	boost::shared_ptr< boost::asio::io_service > io_service(
//		new boost::asio::io_service
//		);
//	boost::shared_ptr< boost::asio::io_service::work > work(
//		new boost::asio::io_service::work(*io_service)
//		);
//
//	global_stream_lock.lock();
//	std::cout << "[" << boost::this_thread::get_id()
//		<< "] Press [return] to exit." << std::endl;
//	global_stream_lock.unlock();
//
//	boost::thread_group worker_threads;
//	for (int x = 0; x < 4; ++x)
//	{
//		worker_threads.create_thread(boost::bind(&WorkerThread, io_service));
//	}
//
//	std::cin.get();
//
//	io_service->stop();
//
//	worker_threads.join_all();
//
//	return 0;
//}
