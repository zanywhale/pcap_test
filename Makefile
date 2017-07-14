#Makefile
all: pcap_test

pcap_test: main.o 
	gcc -o pcap_test main.o -lpcap

main.o: net_header.h main.c

#net_header.o: net_header.h

clean:
	#rm -f pcap_test
	rm -f *.o


