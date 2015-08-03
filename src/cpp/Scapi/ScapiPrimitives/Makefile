include ../rules/make.hdr

Program=ScapiPrimitives.$(EXE_EXT)
all:: $(Program)

$(Program):	$(patsubst %.cpp,%.$(OBJ_EXT),$(wildcard *.cpp))
	$(LINK.cpp)

Main.obj: Main.cpp
	cl -c Main.cpp

tests:: all
	$(Program)