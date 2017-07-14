#Makefile
all: pcap_test

pcap_test: main.o header.o
	gcc -o pcap_test main.o header.o -lpcap

main.o: header.h main.c

header.o: header.h header.c

clean:
	#rm -f pcap_test
	rm -f *.o


