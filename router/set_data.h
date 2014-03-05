#ifndef SET_DATA_H
#define SET_DATA_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

/*#include <sys/types.h>*/


void set_ether_hdr(uint8_t* sp, uint8_t dhost[], uint8_t shost[], \
                    uint16_t type);
void set_ip_hdr(uint8_t* sp, uint8_t os, uint16_t len, uint16_t id, \
                uint16_t off, uint8_t ttl, uint8_t pro, \
                uint32_t src, uint32_t dst);
void set_arp_hdr(uint8_t* sp, unsigned short hrd, unsigned short pro, \
                unsigned char hln, unsigned char pln, unsigned short op, \
                unsigned char sha[], uint32_t sip, \
                unsigned tha[], uint32_t tip);
void set_icmp_hdr(uint8_t* sp, uint8_t icmp_type, uint8_t icmp_code);

#endif
