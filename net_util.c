#include "net_header.h"
#include "all_header.h"
void print_boundary(){
	printf("************************************************\n");
}

void print_MAC_addr(Ethernet_H *tmp){
	printf("Ethernet Dest MAC Addr : %02X:%02X:%02X:%02X:%02X:%02X\n",\
	tmp->dest[0]&0xff,tmp->dest[1]&0xff,tmp->dest[2]&0xff,\
	tmp->dest[3]&0xff,tmp->dest[4]&0xff,tmp->dest[5]&0xff);
	printf("Ethernet Src MAC Addr: %02X:%02X:%02X:%02X:%02X:%02X\n",\
	tmp->src[0]&0xff,tmp->src[1]&0xff,tmp->src[2]&0xff,\
	tmp->src[3]&0xff,tmp->src[4]&0xff,tmp->src[5]&0xff);
}

void print_TCP_port(Tcp_H *tmp){
	printf("TCP Dest Port : %hu\n", htons(tmp->dst_port));
	printf("TCP Src Port : %hu\n", htons(tmp->src_port));
}

void print_IP_addr(Ip_H *tmp){
	char tmp_buf[20];
	inet_ntop(AF_INET, (const void *)&tmp->src, tmp_buf, sizeof(tmp_buf));
	printf("IP src : %s\n",tmp_buf);
	inet_ntop(AF_INET, (const void *)&tmp->dst, tmp_buf, sizeof(tmp_buf));
	printf("IP dst : %s\n",tmp_buf);
}