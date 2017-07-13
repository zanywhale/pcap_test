#Makefile
all: pcap_test

pcap_test: pcap_test.o
	gcc -o pcap pcap_test.o -lpcap

pcap_test.o: pcap_test.c

clean:
	#rm -f pcap_test
	rm -f *.o


