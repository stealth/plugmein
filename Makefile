#

CXX=c++
CXXFLAGS=-Wall -std=c++11 -pedantic -O2
#DEFS=-DHAVE_IMMEDIATE

all:
	$(CXX) $(CXXFLAGS) $(DEFS) plugmein.cc -lpcap -o plugmein

