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
#include <stdlib.h>
#include <string.h>


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
            /* handle arp request */
            printf("%s\n", "Handle Arp Request.");
            uint8_t* arp_reply_frame = (uint8_t*)malloc(ETHER_HDR_LEN + ARP_HDR_LEN);
            /* ethernet */
            set_ether_hdr(arp_reply_frame, rcv_arhdr->ar_sha, iface->addr, htons(ethertype_arp));
            /* arp */
            set_arp_hdr(arp_reply_frame + ETHER_HDR_LEN, htons(1), rcv_arhdr->ar_pro, \
                        rcv_arhdr->ar_hln, rcv_arhdr->ar_pln, htons(arp_op_reply), \
                        iface->addr, iface->ip, rcv_arhdr->ar_sha, rcv_arhdr->ar_sip);

            printf("print router's arp reply header:\n");
            print_hdrs(arp_reply_frame, len_ether_arp);

            printf("Send arp reply...\n");
            sr_send_packet(sr, arp_reply_frame, len_ether_arp, interface);
        } else if (rcv_ar_op == arp_op_reply) {
            printf("Handle Arp Reply.\n");
            struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), rcv_arhdr->ar_sha, rcv_arhdr->ar_sip);
            if (req != NULL) {
                struct sr_packet* pkt;
                for(pkt = req->packets; pkt != NULL; pkt = pkt->next) {
                    struct sr_if* out_iface = sr_get_interface(sr, pkt->iface);
                    if (out_iface->ip != rcv_arhdr->ar_tip)
                        continue;

                    set_ether_hdr(pkt->buf, rcv_arhdr->ar_sha, out_iface->addr,
                                 htons(ethertype_ip));
                    sr_ip_hdr_t* tmp_iphdr = (sr_ip_hdr_t*)(pkt->buf + ETHER_HDR_LEN);
                    /* if router is target, no need to decrease ttl */
                    if (tmp_iphdr->ip_ttl != 255)
                        dcrs_ip_ttl(pkt->buf + ETHER_HDR_LEN);
                    printf("Send pending packet (due to arp reply received)\n");
                    sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                }
                sr_arpreq_destroy(&(sr->cache), req);
            } else {
                /* received an arp reply but no corresponding packet waiting 
                for it. Just cache the arp entry, which is already done. */
                ;
            }
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

        int ip_cksum = cksum(rcv_iphdr, IP_HDR_LEN);
        if (ip_cksum != 0xffff) {
            fprintf(stderr, "Failed to handle packet, invalid IP header check sum.\n");
            return;
        }

        int len_ether_ip_icmp = ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN;
        int len_ether_ip_icmpt3 = len_ether_ip_icmp + ICMP_DATA_SIZE;

        /* non-IP packet received, send icmp port unreachable, 
           without considering ttl exceed */
        if (is_dst(sr, packet) && rcv_ip_p != ip_protocol_icmp) {
            fprintf(stderr, "Failed to handle packet, UDP or TCP payload received as dest.\n");
            uint8_t* icmp_port_urb_frame = (uint8_t*)malloc(len_ether_ip_icmpt3);
            set_ether_hdr(icmp_port_urb_frame, rcv_ehdr->ether_shost, iface->addr, htons(ethertype_ip));
            set_ip_hdr(icmp_port_urb_frame + ETHER_HDR_LEN, 
                    0, htons(IP_HDR_LEN + ICMP_T3_HDR_LEN), htons(0), htons(0), 64, 
                    ip_protocol_icmp, iface->ip, rcv_iphdr->ip_src);
            set_icmp_t3_hdr(icmp_port_urb_frame + ETHER_HDR_LEN + IP_HDR_LEN, 
                    3, 3, 0, packet + ETHER_HDR_LEN);
            printf("Will send icmp port urb frame:\n");
            print_hdrs(icmp_port_urb_frame, len_ether_ip_icmpt3);
            sr_send_packet(sr, icmp_port_urb_frame, len_ether_ip_icmpt3, interface);
            return;
        }

        /* time exceeded */
        if (rcv_ttl <= 1) {
            fprintf(stderr, "Failed to handle packet, invalid TTL.\n");
            uint8_t* icmp_time_exceed_frame = (uint8_t*)calloc(1, len_ether_ip_icmpt3);
            /* ethernet */
            set_ether_hdr(icmp_time_exceed_frame, rcv_ehdr->ether_shost, iface->addr, htons(ethertype_ip));
            /* ip */
            set_ip_hdr(icmp_time_exceed_frame + ETHER_HDR_LEN, 0, htons(IP_HDR_LEN + ICMP_T3_HDR_LEN), \
                        htons(0), htons(0), 64, ip_protocol_icmp, \
                        iface->ip, rcv_iphdr->ip_src);
            /* icmp t3 */
            set_icmp_t3_hdr(icmp_time_exceed_frame + ETHER_HDR_LEN + IP_HDR_LEN, 11, 0, 0, packet + ETHER_HDR_LEN);
            sr_send_packet(sr, icmp_time_exceed_frame, len_ether_ip_icmpt3, interface);
            return;
        }

        /* destination is me and packet is ICMP */
        if (is_dst(sr, packet) && rcv_ip_p == ip_protocol_icmp) {
            printf("I am the ICMP dest, try to handle.\n");
            sr_icmp_hdr_t* rcv_icmp_hdr = (sr_icmp_hdr_t*)(packet + ETHER_HDR_LEN + IP_HDR_LEN);
            printf("type: %d, code: %d.\n", rcv_icmp_hdr->icmp_type, rcv_icmp_hdr->icmp_code);

            /* only handle icmp echo request */
            if (rcv_icmp_hdr->icmp_type == 8) {
                uint16_t icmp_cksum = cksum(rcv_icmp_hdr, len - ETHER_HDR_LEN - IP_HDR_LEN);
                if (icmp_cksum != 0xffff) {
                    fprintf(stderr, "Failed to handle packet, invalid icmp checksum.\n");
                    return;
                }
                uint32_t ip_src = rcv_iphdr->ip_src;
                /* prepare icmp echo reply frame without ethernet hdr set*/
                uint8_t* icmp_echo_reply_frame = (uint8_t*)calloc(1, len_ether_ip + ICMP_HDR_LEN);
                /* currently dst mac addr is unknown, wait for arp cache lookup */
                set_ip_hdr(icmp_echo_reply_frame + ETHER_HDR_LEN, 
                            0, htons(IP_HDR_LEN + ICMP_HDR_LEN), htons(0), 
                            htons(0), 255, ip_protocol_icmp, 
                            iface->ip, rcv_iphdr->ip_src);
                /* Identifier and Sequence number field (16 bits for each) are necessary */
                set_icmp_hdr(icmp_echo_reply_frame + len_ether_ip, 0, 0, rcv_icmp_hdr->icmp_id, rcv_icmp_hdr->icmp_seq);

                struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_src);
                if (arp_entry == NULL) {
                    /* queue arp request */
                    /* TODO 3 necessary? */
                    sr_arpcache_queuereq(&(sr->cache), ip_src, icmp_echo_reply_frame, len_ether_ip + ICMP_HDR_LEN, interface);
                } else {
                    set_ether_hdr(icmp_echo_reply_frame, arp_entry->mac, 
                                    iface->addr, htons(ethertype_ip));
                    printf("Send icmp echo reply packet\n");
                    sr_send_packet(sr, icmp_echo_reply_frame, len_ether_ip + ICMP_HDR_LEN, interface);
                }
            } else {
                fprintf(stderr, "Failed to handle packet, unsupported icmp type.\n");
                return;
            }
        } else { /* try forward */
            printf("Not the dest, try to forward.\n");
            uint32_t ip_dst = rcv_iphdr->ip_dst;
            /* TODO longest prefix match, current solution is astray 
            because wrong rt_entry is returned when no matching */
            struct sr_rt* rt_entry = sr_get_rt_entry(sr, ip_dst);
            /* no route to the destination IP */
            if (rt_entry == NULL) {
                fprintf(stderr, "Failed to handle packet, no routing table entry matched.\n");
                /* reply icmp net urb (3, 0) */
                int len_ether_ip_icmpt3 = ETHER_HDR_LEN + IP_HDR_LEN + ICMP_T3_HDR_LEN;
                uint8_t* icmp_net_urb_frame = (uint8_t*)malloc(len_ether_ip_icmpt3);
                set_ether_hdr(icmp_net_urb_frame, rcv_ehdr->ether_shost,
                                iface->addr, htons(ethertype_ip));
                set_ip_hdr(icmp_net_urb_frame + ETHER_HDR_LEN, 
                        0, htons(IP_HDR_LEN + ICMP_T3_HDR_LEN), 
                        rcv_iphdr->ip_id, rcv_iphdr->ip_off, 64, 
                        ip_protocol_icmp, iface->ip, rcv_iphdr->ip_src);
                set_icmp_t3_hdr(icmp_net_urb_frame + ETHER_HDR_LEN + IP_HDR_LEN, 
                            3, 0, 0, packet + ETHER_HDR_LEN);
                printf("Send icmp dest net unreachable.\n");
                sr_send_packet(sr, icmp_net_urb_frame, len_ether_ip_icmpt3, interface);
                return;
            }
            char* out_iface_name = rt_entry->interface;
            struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_dst);
            if (arp_entry == NULL) {
                printf("Will queue some arp requests.\n");
                /* no need to send from all iface because out iface already decided by routing table */
                sr_arpcache_queuereq(&(sr->cache), ip_dst, packet, len, out_iface_name);
            } else {
                struct sr_if* out_iface = sr_get_interface(sr, out_iface_name);
                /*uint32_t next_hop_ip = entry->ip;*/
                unsigned char* next_hop_mac = arp_entry->mac;

                uint8_t* forward_packet = (uint8_t*)calloc(1, len);
                memcpy(forward_packet + ETHER_HDR_LEN, packet + ETHER_HDR_LEN, len - ETHER_HDR_LEN);
                set_ether_hdr(forward_packet, next_hop_mac, out_iface->addr, htons(ethertype_ip));
                dcrs_ip_ttl(forward_packet + ETHER_HDR_LEN);
                printf("Will forward this packet:::::::::::\n");
                print_hdrs(forward_packet, len);
                sr_send_packet(sr, forward_packet, len, out_iface_name);
                free(arp_entry);
            }
        }
    }

}/* end sr_ForwardPacket */

