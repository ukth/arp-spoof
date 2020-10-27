LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o
	g++ -std=c++11 -Wall -g -o arp-spoof main.o arphdr.o ethhdr.o ip.o mac.o -lpcap


main.o: main.cpp
	g++ -std=c++11 -Wall -g -c -o main.o main.cpp

arphdr.o: arphdr.cpp arphdr.h
	g++ -std=c++11 -Wall -g -c -o arphdr.o arphdr.cpp

ethhdr.o: ethhdr.cpp ethhdr.h
	g++ -std=c++11 -Wall -g -c -o ethhdr.o ethhdr.cpp

ip.o: ip.cpp ip.h
	g++ -std=c++11 -Wall -g -c -o ip.o ip.cpp

mac.o: mac.cpp mac.h
	g++ -std=c++11 -Wall -g -c -o mac.o mac.cpp

clean:
	rm -f arp-spoof *.o
