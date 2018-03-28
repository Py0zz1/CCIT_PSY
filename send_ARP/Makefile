all : sniffing_psy

sniffing_psy: main.o
	g++ -g -o sniffing_psy main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f sniffing_psy
	rm -f *.o
	