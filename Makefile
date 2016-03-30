# CXX=g++
CXXFLAGS=-c -Wall -Wextra -Werror -std=c++11
LDFLAGS=-lpcap
SOURCES=main.cpp PcapListener.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=NetworkStats

all: $(SOURCES) $(EXECUTABLE) 

$(EXECUTABLE) : $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm $(EXECUTABLE)
	rm $(OBJECTS)
