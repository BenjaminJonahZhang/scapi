include ./rules/make.hdr
Program=ScapiTests.$(EXE_EXT)

SLib = scapi.$(LIB_EXT)
CPP_FILES :=$(wildcard src/*.cpp)
OBJ_FILES := $(patsubst src/%.cpp,obj/%.$(OBJ_EXT),$(CPP_FILES))
OBJ_FILES_NO_TESTS := $(filter-out obj/tests.$(OBJ_EXT), $(OBJ_FILES))
OUT_DIR = obj

CPP_OPTIONS:= -std=c++11 -lcrypto++ -lcrypto -L/usr/lib
CPP_LINK_OPTIONS:= -lcrypto++ -lcrypto

all:: directories $(SLib) 

directories: $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(SLib): $(OBJ_FILES_NO_TESTS)
	ar ru $@ $^ 
	ranlib $@

$(Program):	$(OBJ_FILES) 
	$(LINK.cpp)

obj/%.$(OBJ_EXT): src/%.cpp
	$(COMPILE.cpp) 

tests:: all
	$(Program)

clean::
	@echo "cleaning .obj files"
	@rm -f $(OUT_DIR)/*.$(OBJ_EXT)
	@echo "cleaning executable"
	@rm -f $(Program)
	@echo "cleaning lib"
	@rm -f $(SLib)
