# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-maliciousYaoUtil

# compilation options
CXX=g++
CXXFLAGS=-fPIC -maes

# openssl dependency
OPENSSL_INCLUDES = -I$(prefix)/ssl/include
OPENSSL_LIB_DIR = -L$(prefix)/ssl/lib
OPENSSL_LIB = -lssl -lcrypto


SOURCES = MaliciousYaoUtil.cpp Util.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libMaliciousYaoUtilJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(OPENSSL_INCLUDES) \
	$(OPENSSL_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(OPENSSL_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
	rm -f *.dylib
	rm -f *.jnilib
