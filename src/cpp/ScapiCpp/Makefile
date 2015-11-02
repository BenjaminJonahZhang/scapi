include ./rules/make.hdr

Program=ScapiTests.$(EXE_EXT)

CPP_FILES :=$(wildcard src/*.cpp)
OBJ_FILES := $(patsubst src/%.cpp,obj/%.$(OBJ_EXT),$(CPP_FILES))

CPP_OPTIONS:= -std=c++11 -lcrypto++ -ilcrypto -L/usr/lib

all:: $(Program)

$(Program):	$(OBJ_FILES)
	$(LINK.cpp)

obj/%.$(OBJ_EXT): src/%.cpp
	$(RAW_COMPILE.cpp) 

tests:: all
	$(Program)