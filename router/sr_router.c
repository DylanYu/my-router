/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "set_data.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
    printf("*****Received packet is:******\n");
    print_hdrs(packet, len);

    printf("%s\n", "--------My print-------");
    sr_ethernet_hdr_t* rcv_ehdr = (sr_ethernet_hdr_t*)packet;
    uint16_t rcv_ether_type = ntohs(rcv_ehdr->ether_type);
    printf("Interface: %s.\n", interface);

    struct sr_if* iface = sr_get_interface(sr, interface);
    assert(iface);

    if (rcv_ether_type == ethertype_arp) {
        printf("%s\n", "This is an ARP packet.");
        int len_ether_arp = ETHER_HDR_LEN + ARP_HDR_LEN;
        if (len < len_ether_arp) {
            fprintf(stderr, "Failed to handle packet, insufficient length.\n");
            return;
        }
        if (!is_dst(sr, packet)) {
            fprintf(stderr, "Will not handle packet, this packet is not targeted to me.\n");
            return;
        }

        sr_arp_hdr_t* rcv_arhdr = (sr_arp_hdr_t*)(packet + ETHER_HDR_LEN);
        unsigned short rcv_ar_op = ntohs(rcv_arhdr->ar_op);
        if (rcv_ar_op == arp_op_request) {
            printf("%s\n", "Handle Arp Request");
            uint8_t* arp_reply_frame = (uint8_t*)malloc(ETHER_HDR_LEN + ARP_HDR_LEN);
            /* ethernet */
            set_ether_hdr(arp_reply_frame, rcv_arhdr->ar_sha, iface->addr, htons(ethertype_arp));
            /* arp */
            set_arp_hdr(arp_reply_frame + ETHER_HDR_LEN, rcv_arhdr->ar_hrd, rcv_arhdr->ar_pro, \
                        rcv_arhdr->ar_hln, rcv_arhdr->ar_pln, htons(arp_op_reply), \
                        iface->addr, iface->ip, rcv_arhdr->ar_sha, rcv_arhdr->ar_sip);

            printf("print my header\n");
            print_hdrs(arp_reply_frame, len_ether_arp);
            printf("interface: %s\n", interface);

            printf("===SENDING===\n");
            sr_send_packet(sr, arp_reply_frame, len_ether_arp, interface);
        } else if (rcv_ar_op == arp_op_reply) {
            printf("Handle Arp Reply.\n");
            sr_arp_hdr_t* arp_reply = (sr_arp_hdr_t*)calloc(1, sizeof(sr_arp_hdr_t));

            free(arp_reply);
        } else {
            fprintf(stderr, "Failed to handle packet. unknown ARP type.\n");
            return;
        }
    } else if (rcv_ether_type == ethertype_ip) {
        printf("%s\n", "This is an IP packet.\n");
        int len_ether_ip = ETHER_HDR_LEN + IP_HDR_LEN;
        if (len < len_ether_ip) {
            fprintf(stderr, "Failed to handle packet, insufficient length.\n");
            return;
        }
        sr_ip_hdr_t* rcv_iphdr = (sr_ip_hdr_t*)(packet + ETHER_HDR_LEN);
        uint8_t rcv_ttl = rcv_iphdr->ip_ttl;
        uint8_t rcv_ip_p = rcv_iphdr->ip_p;
        printf("ip TTL: %d\n", rcv_ttl);
        printf("ip protocol: %d\n", rcv_ip_p);

        int ip_cksum = cksum(rcv_iphdr, IP_HDR_LEN);
        if (ip_cksum != 0xffff) {
            fprintf(stderr, "Failed to handle packet, invalid IP header check sum.\n");
            return;
        }

        /* time exceeded */
        if (rcv_ttl <= 0) {
            fprintf(stderr, "Failed to handle packet, invalid TTL.\n");
            uint8_t* icmp_time_exceed_frame = (uint8_t*)calloc(1, ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN);
            /* ethernet */
            set_ether_hdr(icmp_time_exceed_frame, rcv_ehdr->ether_shost, iface->addr, htons(ethertype_ip));
            /* ip */
            set_ip_hdr(icmp_time_exceed_frame + ETHER_HDR_LEN, 0, htons(IP_HDR_LEN + ICMP_HDR_LEN), \
                        htons(0), htons(0), 64, ip_protocol_icmp, \
                        iface->ip, rcv_iphdr->ip_src);
            /* icmp */
            /* TODO randomize id, rewrite seq */
            set_icmp_hdr(icmp_time_exceed_frame + ETHER_HDR_LEN + IP_HDR_LEN, 11, 0, 0, 0);

            sr_send_packet(sr, icmp_time_exceed_frame, ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN, interface);
            return;
        }

        if (is_dst(sr, packet)) { /* dest is me */
            printf("I am the dest, try to handle.\n");
            if (rcv_ip_p == ip_protocol_icmp) {
                printf("Handle ICMP packet.\n");
                sr_icmp_hdr_t* rcv_icmp_hdr = (sr_icmp_hdr_t*)(packet + ETHER_HDR_LEN + IP_HDR_LEN);
                printf("type: %d, code: %d.\n", rcv_icmp_hdr->icmp_type, rcv_icmp_hdr->icmp_code);
                /* TODO icmp cksum */
                /*printf("icmp:\n");
                print_hdr_icmp(rcv_icmp_hdr);
                uint16_t ch_sum = cksum(rcv_icmp_hdr, ICMP_HDR_LEN - 4);
                printf("icmp ch_sum: %x\n", ch_sum);*/

                if (rcv_icmp_hdr->icmp_type == 8) { /* echo request */
                    uint8_t* icmp_echo_reply_frame = (uint8_t*)calloc(1, len_ether_ip + ICMP_HDR_LEN);
                    /* TODO issue arp request */
                    set_ether_hdr(icmp_echo_reply_frame, \
                                    rcv_ehdr->ether_shost, \
                                    iface->addr, \
                                    htons(ethertype_ip));
                    set_ip_hdr(icmp_echo_reply_frame + ETHER_HDR_LEN, \
                                0, htons(IP_HDR_LEN + ICMP_HDR_LEN), htons(0), \
                                htons(0), 64, ip_protocol_icmp, \
                                iface->ip, rcv_iphdr->ip_src);
                    /* Identifier and Sequence number field (16 bits for each) are necessary */
                    set_icmp_hdr(icmp_echo_reply_frame + len_ether_ip, 0, 0, rcv_icmp_hdr->icmp_id, rcv_icmp_hdr->icmp_seq);

                    sr_send_packet(sr, icmp_echo_reply_frame, len_ether_ip + ICMP_HDR_LEN, interface);
                    printf("==Send icmp echo reply packet==\n");
                } else {
                    fprintf(stderr, "Failed to handle packet, ICMP type unsupported.\n");
                    return;
                }
            } else {
                fprintf(stderr, "Failed to handle packet, UDP or TCP payload received as dest.\n");
                /* TODO send icmp port unreachable bacl */
                return;
            }
            ;
        } else { /* try forward */
            printf("Not the dest, try to forward.\n");
        }
    }

}/* end sr_ForwardPacket */

