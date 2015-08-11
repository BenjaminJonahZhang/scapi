include ./rules/make.hdr

INCLUDES+= "/program files (x86)/Boost/boost_1_58_0"

Program=ScapiTests.$(EXE_EXT)
CPP_FILES :=$(wildcard src/*.cpp)

OBJ_FILES := $(patsubst src/%.cpp,obj/%.$(OBJ_EXT),$(CPP_FILES))

all:: $(Program)

$(Program):	$(OBJ_FILES)
	$(LINK.cpp)

obj/%.$(OBJ_EXT): src/%.cpp
	$(RAW_COMPILE.cpp) 

tests:: all
	$(Program)