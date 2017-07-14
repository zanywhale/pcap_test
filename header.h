#include <stdio.h>

#define ETHERNET_ALEN 6

typedef struct ethernet{
    unsigned char dest[ETHERNET_ALEN];
    unsigned char src[ETHERNET_ALEN];
    unsigned short int type;
}ethernet_h;

typedef struct ip{
    unsigned char v:4, hl:4;/* this means that each member is 4 bits */
    unsigned char tos;       //1 Byte
    unsigned short int len;  //2 Byte
    unsigned short int id;   //2 Byte
    unsigned short int off;  //2 Byte
    unsigned char ttl;       //1 Byte
    unsigned char p;         //1 Byte
    unsigned short int sum;  //2 Byte
    unsigned int src;        //4 Byte
    unsigned int dst;        //4 Byte
}ip_h;

typedef struct tcp{
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned int seq;
    unsigned int ack;
    unsigned char  data_offset;  // 4 bits
    unsigned char  flags;
    unsigned short int window_size;
    unsigned short int checksum;
    unsigned short int urgent_p;
}tcp_h;