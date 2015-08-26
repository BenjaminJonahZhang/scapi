BOOST_ROOT= "/program files (x86)/Boost/boost_1_58_0"
GMP_DIR = "/code/gmp_static"

include ./rules/make.hdr

INCLUDES+= $(BOOST_ROOT)
INCLUDES+= $(GMP_DIR)

CPP_LINK_OPTIONS+= /LIBPATH:"/program files (x86)/Boost/boost_1_58_0/stage/lib"
CPP_LINK_OPTIONS+= /LIBPATH:/code/scapi/assets/gmp/lib
CPP_LINK_OPTIONS+= /LIBPATH:/code/scapi/assets/gmp/lib

LIBS = libgmp-10

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