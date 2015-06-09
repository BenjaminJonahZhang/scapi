# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-openssl

# compilation options
CXX=g++
CXXFLAGS=-fPIC -maes

# openssl dependency
SCGARBLECIRCUITNOFIXEDKEY_INCLUDES = -I$(prefix)/include/ScGarbledCircuitNoFixedKey
#-I/usr/lib/jvm/java-7-openjdk-amd64/include
SCGARBLECIRCUITNOFIXEDKEY_LIB_DIR = -L$(prefix)/lib
SCGARBLECIRCUITNOFIXEDKEY_LIB = -lScGarbledCircuitNoFixedKey

SOURCES = ScGarbledCircuitNoFixedKey.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libScGarbledCircuitNoFixedKeyJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(SCGARBLECIRCUITNOFIXEDKEY_INCLUDES) \
	$(SCGARBLECIRCUITNOFIXEDKEY_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(SCGARBLECIRCUITNOFIXEDKEY_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(SCGARBLECIRCUITNOFIXEDKEY_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
	rm -f *.dylib
	rm -f *.jnilib
