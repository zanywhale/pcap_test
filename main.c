#include "net_header.h"
#include "net_util.h"
#include "all_header.h"


int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 80";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr *header; /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    int res;
    // struct
    Ethernet_H *eth_h = malloc(sizeof(Ethernet_H));
    Ip_H *ip_h = malloc(sizeof(Ip_H));
    Tcp_H *tcp_h = malloc(sizeof(Tcp_H));

    if (argc == 2){
        printf("Need argv[1]\n");
        exit(1);
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
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
        if(res == 1){
            eth_h = (Ethernet_H *)packet;
            print_boundary();
            print_MAC_addr(eth_h);
            if (htons(eth_h->type) == ETHERTYPE_IP){
                ip_h = (Ip_H *)(packet+sizeof(Ethernet_H));
                print_IP_addr(ip_h);
                switch (ip_h->p){
                    case IPPROTO_TCP:
                        tcp_h = (Tcp_H *)(packet+sizeof(Ethernet_H)+(((ip_h->chk)&0xf)*4));
                        print_TCP_port(tcp_h);
                        if(((((tcp_h->data_offset)>>4)*4) + ((ip_h->chk)&0xf)*4) != ntohs(ip_h->len))
                            printf("Data : %s\n",(packet+sizeof(Ethernet_H)+(((ip_h->chk)&0xf)*4)+(((tcp_h->data_offset)>>4)*4)));
                        break;
                }
            }
            print_boundary();
        }
    }
    /* And close the session */
    pcap_close(handle);
    return 0;
}
