#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "net_header.h"

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int res;

	// struct
	Ethernet_H *eth_h = malloc(sizeof(Ethernet_H));
	Ip_H *ip_h = malloc(sizeof(Ip_H));
	Tcp_H *tcp_h = malloc(sizeof(Tcp_H));

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	while(1){
		res = pcap_next_ex(handle, &header, &packet);
		/* Print its length */
		if(res){
			eth_h = (Ethernet_H *)packet;
			ip_h = (Ip_H *)(packet+sizeof(Ethernet_H));
			tcp_h = (Tcp_H *)(packet+sizeof(Ethernet_H)+sizeof(Ip_H));
			printf("************************************************\n")
			printf("Ethernet Dest : %02X:%02X:%02X:%02X:%02X:%02X\n",\
				eth_h->dest[0]&0xff,eth_h->dest[1]&0xff,eth_h->dest[2]&0xff,\
				eth_h->dest[3]&0xff,eth_h->dest[4]&0xff,eth_h->dest[5]&0xff);
			printf("Ethernet src : %02X:%02X:%02X:%02X:%02X:%02X\n",\
				eth_h->src[0]&0xff,eth_h->src[1]&0xff,eth_h->src[2]&0xff,\
				eth_h->src[3]&0xff,eth_h->src[4]&0xff,eth_h->src[5]&0xff);
		}
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}
