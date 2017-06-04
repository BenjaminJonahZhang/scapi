# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-otextension

# compilation options
CXX=g++-4.9
CXXFLAGS=-std=c++0x -g -fPIC

# dependencies
LIBMIRACL = $(libscapi_prefix)/lib/libmiracl.a

INCLUDES=-I$(libscapi_prefix)/include -I$(prefix)/ssl/include -I$(JAVA_HOME)/include/ -I$(JAVA_HOME)/include/darwin/ -I$(JAVA_HOME)/include/linux
LIBRARIES_DIR=-L$(prefix)/ssl/lib -L$(libdir) -L$(libscapi_prefix)/lib
LIBRARIES=$(INCLUDE_ARCHIVES_START) $(LIBMIRACL)  -lssl -lcrypto -lMaliciousOTExtension $(INCLUDE_ARCHIVES_END)

# objects
OT_JNI_OBJECTS = ConnectionManager.o OTExtensionMaliciousCommonInterface.o OTExtensionMaliciousReceiverInterface.o OTExtensionMaliciousSenderInterface.o \
OTExtensionMaliciousReceiver.o OTExtensionMaliciousSender.o CommunicationSetup.o 

## targets ##
# all: libMaliciousOtExtensionJavaInterface$(JNI_LIB_EXT) # mainSender.exe mainReceiver.exe

# main target - linking individual *.o files
libMaliciousOtExtensionJavaInterface$(JNI_LIB_EXT): $(OT_JNI_OBJECTS)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OT_JNI_OBJECTS) $(INCLUDES) $(LIBRARIES_DIR) $(LIBRARIES)

mainSender.exe: $(OT_JNI_OBJECTS) mainSender.cpp
	$(CXX) -o $@ $(OT_JNI_OBJECTS) mainSender.cpp $(INCLUDES) $(LIBRARIES_DIR) $(LIBRARIES)

mainReceiver.exe: $(OT_JNI_OBJECTS) mainReceiver.cpp
	$(CXX) -o $@ $(OT_JNI_OBJECTS) mainReceiver.cpp $(INCLUDES) $(LIBRARIES_DIR) $(LIBRARIES)

ConnectionManager.o: ConnectionManager.cpp
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)
	
CommunicationSetup.o: CommunicationSetup.cpp
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousCommonInterface.o: OTExtensionMaliciousCommonInterface.cpp ConnectionManager.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousReceiverInterface.o: OTExtensionMaliciousReceiverInterface.cpp OTExtensionMaliciousCommonInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousSenderInterface.o: OTExtensionMaliciousSenderInterface.cpp OTExtensionMaliciousCommonInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousReceiver.o: OTExtensionMaliciousReceiver.cpp OTExtensionMaliciousReceiverInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousSender.o: OTExtensionMaliciousSender.cpp OTExtensionMaliciousSenderInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.jnilib
	rm -f *.dylib
	rm -f *.exe
