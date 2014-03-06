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
    print_hdrs(packet, len);

    printf("%s\n", "--------My print-------");
    sr_ethernet_hdr_t* rcv_ehdr = (sr_ethernet_hdr_t*)packet;
    uint16_t rcv_ether_type = ntohs(rcv_ehdr->ether_type);
    printf("Interface: %s.\n", interface);

    struct sr_if* iface = sr_get_interface(sr, interface);
    if (iface == NULL) {
        fprintf(stderr, "Failed to handle packet, invalid interface.\n");
        return;
    }

    if (rcv_ether_type == ethertype_arp) {
        printf("%s\n", "This is an ARP packet.");
        int len_ether_arp = ETHER_HDR_LEN + ARP_HDR_LEN;
        if (len < len_ether_arp) {
            fprintf(stderr, "Failed to handle packet, insufficient length.\n");
            return;
        }
        sr_arp_hdr_t* rcv_arhdr = (sr_arp_hdr_t*)(packet + ETHER_HDR_LEN);
        if (rcv_arhdr->ar_tip != iface->ip) {
            fprintf(stderr, "Will not handle packet, this packet is not targeted to me.\n");
            return;
        }

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
            sr_arp_hdr_t* arp_reply = (sr_arp_hdr_t*)malloc(sizeof(sr_arp_hdr_t));

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
        uint8_t ttl = rcv_iphdr->ip_ttl;
        if (ttl <= 0) {
            fprintf(stderr, "Failed to handle packet, invalid TTL.\n");
            uint8_t* icmp_time_exceed_frame = (uint8_t*)malloc(ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN);
            /* ethernet */
            set_ether_hdr(icmp_time_exceed_frame, rcv_ehdr->ether_shost, iface->addr, htons(ethertype_ip));
            /* ip */
            set_ip_hdr(icmp_time_exceed_frame + ETHER_HDR_LEN, 0, htons(IP_HDR_LEN + ICMP_HDR_LEN), \
                        htons(0), htons(0), 64, ip_protocol_icmp, \
                        iface->ip, rcv_iphdr->ip_src);
            /* icmp */
            set_icmp_hdr(icmp_time_exceed_frame + ETHER_HDR_LEN + IP_HDR_LEN, 11, 0);

            sr_send_packet(sr, icmp_time_exceed_frame, ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN, interface);
            return;
        }
        uint8_t ip_protocol = rcv_iphdr->ip_p;
        printf("ip TTL: %d\n", ttl);
        printf("ip protocol: %d\n", ip_protocol);
    }

}/* end sr_ForwardPacket */

