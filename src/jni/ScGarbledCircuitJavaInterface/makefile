# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-openssl

# compilation options
CXX=g++
CXXFLAGS=-fPIC -maes

# openssl dependency
SCGARBLECIRCUIT_INCLUDES = -I$(prefix)/include/ScGarbledCircuit
#-I/usr/lib/jvm/java-7-openjdk-amd64/include
SCGARBLECIRCUIT_LIB_DIR = -L$(prefix)/lib
SCGARBLECIRCUIT_LIB = -lScGarbledCircuit

SOURCES = ScGarbledCircuit.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libScGarbledCircuitJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(SCGARBLECIRCUIT_INCLUDES) \
	$(SCGARBLECIRCUIT_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(SCGARBLECIRCUIT_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(SCGARBLECIRCUIT_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
	rm -f *.dylib
	rm -f *.jnilib
