PROGRAM= tests.exe

all:: $(PROGRAM)

$(PROGRAM): 
	g++ -std=c++11 -o tests.exe tests.cpp ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -L~/boost/stage/lib/ -lpthread -lboost_system -lboost_log

tests:: all
	$(Program)

clean::
	rm tests.exe



