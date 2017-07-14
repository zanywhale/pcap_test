#Makefile
all: pcap_test

pcap_test: main.o net_header.o
	gcc -o pcap_test main.o net_header.o -lpcap

main.o: net_header.h main.c

net_header.o: net_header.h net_header.c

clean:
	#rm -f pcap_test
	rm -f *.o


