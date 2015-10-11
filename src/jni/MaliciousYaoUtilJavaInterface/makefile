# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-maliciousYaoUtil

# compilation options
CXX=g++
CXXFLAGS=-fPIC 

SOURCES = MaliciousYaoUtil.cpp Util.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libMaliciousYaoUtilJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) 

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
	rm -f *.dylib
	rm -f *.jnilib
