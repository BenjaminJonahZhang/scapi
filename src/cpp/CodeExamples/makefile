all:: 
	sed -i'' 's/main.*(/main(/' comm_example.cpp
	 g++ -std=c++11 -o comm_example.exe comm_example.cpp -DBOOST_LOG_DYN_LINK=1 ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -L~/boost/stage/lib/ -lboost_log -lboost_system -lboost_thread -lpthread
	sed -i'' 's/main.*(/main(/' simple_log.cpp
	g++ -std=c++11 -static -o simple_log.exe simple_log.cpp ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -L~/boost/stage/lib/ -lpthread -lboost_system -lboost_log
	sed -i'' 's/main.*(/main(/'  simple_sha1.cpp
	g++ -std=c++11 -static -o  simple_sha1.exe  simple_sha1.cpp ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -L~/boost/stage/lib/ -lpthread -lboost_system -lboost_log	


tests:: all
	$(Program)

clean::
	rm tests.exe



