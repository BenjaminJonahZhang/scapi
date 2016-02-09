all:: 
	sed -i'' 's/main.*(/main(/' comm_example.cpp
	 g++ -std=c++11 -I../../../../boost_1_60_0 -o comm_example.exe comm_example.cpp ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -lboost_log -lboost_system -lboost_thread -lpthread
	sed -i'' 's/main.*(/main(/' simple_dlog.cpp
	g++ -std=c++11 -I../../../../boost_1_60_0 -static -o simple_dlog.exe simple_dlog.cpp ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -lpthread -lboost_system -lboost_log
	sed -i'' 's/main.*(/main(/'  simple_sha1.cpp
	g++ -std=c++11 -I../../../../boost_1_60_0 -static -o  simple_sha1.exe  simple_sha1.cpp ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -lpthread -lboost_system -lboost_log	


tests:: all
	$(Program)

clean::
	rm ./*.exe



