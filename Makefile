#Makefile
all: pcap_test

pcap_test: main.o net_util.o
	gcc -o pcap_test main.o net_util.o -lpcap

main.o: net_header.h main.c

net_util.o: net_util.h net_util.c

clean:
	#rm -f pcap_test
	rm -f *.o


