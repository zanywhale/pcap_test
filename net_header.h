#include <stdint.h>
#define ETHERNET_ALEN 6

typedef struct _ethernet{
    uint8_t dest[ETHERNET_ALEN];
    uint8_t src[ETHERNET_ALEN];
    uint16_t type;
}__attribute__((packed))Ethernet_H;

typedef struct _ip{
    uint8_t v:4, hl:4;/* this means that each member is 4 bits */
    uint8_t tos;       //1 Byte
    uint16_t len;  //2 Byte
    uint16_t id;   //2 Byte
    uint16_t off;  //2 Byte
    uint8_t ttl;       //1 Byte
    uint8_t p;         //1 Byte
    uint16_t sum;  //2 Byte
    uint32_t src;        //4 Byte
    uint32_t dst;        //4 Byte
}__attribute__((packed))Ip_H;

typedef struct _tcp{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;  // 4 bits
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_p;
}__attribute__((packed))Tcp_H;
