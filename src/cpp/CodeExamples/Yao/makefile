all:: YaoParties.o
	sed -i'' 's/main.*(/main(/' App1.cpp
	sudo cp /usr/ssl/lib/libcrypto.so.1.1.0 /usr/lib/
	g++ -std=c++11 -o App1.exe YaoParties.o App1.cpp -DBOOST_LOG_DYN_LINK=1 ../../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -lOTExtension -lScGarbledCircuit -lboost_log -lboost_system -lboost_thread -lpthread -maes -mpclmul

YaoParties.o : 
	g++ -c -std=c++11 -o YaoParties.o YaoParties.cpp -DBOOST_LOG_DYN_LINK -maes -mpclmul

tests:: all
	$(Program)

clean::
	rm YaoParties.o
	rm App1.exe



