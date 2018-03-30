all : send_ARP

send_ARP : main.o
	g++ -g -std=c++11 -o send_ARP main.o -lpcap -lpthread

main.o : header.h
	g++ -g -c -std=c++11 -o main.o main.cpp

clean :
	rm -f *.o send_ARP

