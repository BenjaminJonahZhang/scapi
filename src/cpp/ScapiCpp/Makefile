Program=ScapiTests.$(EXE_EXT)

OBJ_EXT:= o
EXE_EXT:= exe # for portability sake, just use .exe as an executable name on all platforms.
LIB_EXT:= a
DLL_EXT:= so

OPT_LEVEL=  Optimized
DEBOPT = $(subst Optimized,-O2,$(subst Debug,-g3 -fno-inline -O0,$(OPT_LEVEL)))

CPP_FILES :=$(wildcard src/*.cpp)
OBJ_FILES := $(patsubst src/%.cpp,obj/%.$(OBJ_EXT),$(CPP_FILES))
CPP_OPTIONS:= -std=c++11 -lcrypto++ -lcrypto -L/usr/lib
DLL_OPTIONS=


LINK.cpp =  g++ -o$@ $(filter %.$(OBJ_EXT),$+) $(filter %.$(LIB_EXT),$+) $(filter %.$(DLL_EXT),$+) $(CPP_LINK_OPTIONS) 
RAW_COMPILE.cpp  =  g++ -o$@ $(patsubst %, -I%, $(INCLUDES)) -I $(MAKE_RULES_DIR) $(CPP_OPTIONS) $(DLL_OPTIONS) -c  $<

all:: $(Program) $(SLib)

$(SLib): $(OBJ_FILES)
       ar ru $@ $^ 
       ranlib $@

$(Program):	$(OBJ_FILES) 
	$(LINK.cpp)

obj/%.$(OBJ_EXT): src/%.cpp
	$(COMPILE.cpp) 

tests:: all
	$(Program)

clean:
	@echo "cleaning .obj files"
	@rm -f obj/*.obj
	@echo "cleaning executable"
	@rm -f $(Program)
	@echo "cleaning lib"
	@rm -f $(SLib)