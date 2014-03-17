#include <string.h>

#include "set_data.h"
#include "sr_protocol.h"
#include "sr_utils.h"

void set_ether_hdr(uint8_t* sp, uint8_t dhost[], uint8_t shost[], \
                    uint16_t type) {
    sr_ethernet_hdr_t* hdr = (sr_ethernet_hdr_t*)sp;
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        hdr->ether_dhost[i] = dhost[i];
        hdr->ether_shost[i] = shost[i];
    }
    hdr->ether_type = type;
}

void set_ip_hdr(uint8_t* sp, uint8_t tos, uint16_t len, uint16_t id, \
                uint16_t off, uint8_t ttl, uint8_t pro, \
                uint32_t src, uint32_t dst) {
    memset(sp +  10, 0 , 2);
    sr_ip_hdr_t* hdr = (sr_ip_hdr_t*)sp;
    hdr->ip_v = 4;
    hdr->ip_hl = 5;
    hdr->ip_tos = tos;
    hdr->ip_len = len;
    hdr->ip_id = id;
    hdr->ip_off = off;
    hdr->ip_ttl = ttl; 
    hdr->ip_p = pro;
    hdr->ip_src = src;
    hdr->ip_dst = dst;
    hdr->ip_sum = cksum(hdr, IP_HDR_LEN);
}

void dcrs_ip_ttl(uint8_t* sp) {
    sr_ip_hdr_t* hdr = (sr_ip_hdr_t*)sp;
    set_ip_hdr(sp, hdr->ip_tos, hdr->ip_len, hdr->ip_id, hdr->ip_off, \
                hdr->ip_ttl - 1, hdr->ip_p, hdr->ip_src, hdr->ip_dst);
}

void set_arp_hdr(uint8_t* sp, unsigned short hrd, unsigned short pro, \
                unsigned char hln, unsigned char pln, unsigned short op, \
                unsigned char sha[], uint32_t sip, \
                unsigned char tha[], uint32_t tip) {
    sr_arp_hdr_t* hdr = (sr_arp_hdr_t*)sp;
    hdr->ar_hrd = hrd;
    hdr->ar_pro = pro;
    hdr->ar_hln = hln;
    hdr->ar_pln = pln;
    hdr->ar_op = op;
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        hdr->ar_sha[i] = sha[i];
        hdr->ar_tha[i] = tha[i];
    }
    hdr->ar_sip = sip;
    hdr->ar_tip = tip;
}

void set_icmp_hdr(uint8_t* sp, uint8_t type, uint8_t code, uint16_t id, uint16_t seq) {
    memset(sp + 2, 0, 6);
    sr_icmp_hdr_t* hdr = (sr_icmp_hdr_t*)sp;
    hdr->icmp_type = type;
    hdr->icmp_code = code;
    hdr->icmp_id = id;
    hdr->icmp_seq = seq;
    hdr->icmp_sum = cksum(hdr, ICMP_HDR_LEN);
}

void set_icmp_t3_hdr(uint8_t* sp, uint8_t type, uint8_t code, uint16_t next_mtu, uint8_t* data) {
    memset(sp + 2, 0, 6);
    sr_icmp_t3_hdr_t* hdr = (sr_icmp_t3_hdr_t*)sp;
    hdr->icmp_type = type;
    hdr->icmp_code = code;
    hdr->next_mtu = next_mtu;
    memcpy(sp + 8, data, ICMP_DATA_SIZE);
    hdr->icmp_sum = cksum(hdr, ICMP_T3_HDR_LEN);
}
