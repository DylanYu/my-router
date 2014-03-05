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
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
    uint16_t ether_type = ntohs(ehdr->ether_type);
    printf("Type: %04X\n", ether_type);
    uint8_t* dst = ehdr->ether_dhost;
    uint8_t* src = ehdr->ether_shost;
    printf("Dst mac: %02X:%02X:%02X:%02X:%02X:%02X\n", *dst, *(dst+1), *(dst+2), *(dst+3), *(dst+4), *(dst+5));
    printf("Src mac: %02X:%02X:%02X:%02X:%02X:%02X\n", src[0], src[1], src[2], src[3], src[4], src[5]);
    printf("Interface: %s.\n", interface);

    if (ether_type == ethertype_arp) {
        printf("%s\n", "This is an ARP packet.");
        int len_ether_arp = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        if (len < len_ether_arp) {
            fprintf(stderr, "Failed to handle packet, insufficient length.\n");
            return;
        }
        /* handle arp */
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        unsigned short ar_op = ntohs(arp_hdr->ar_op);
        if (ar_op == arp_op_request) {
            printf("%s\n", "Arp Request");
            /* in fact this transform isn't necessary cause if_list store ip with transform*/
            uint32_t tip = ntohl(arp_hdr->ar_tip);
            print_addr_ip_int(tip);
            struct sr_if* iface = sr->if_list;
            while (iface != NULL) {
                if (tip == ntohl(iface->ip)) {
                    /* target is me */
                    printf("this is me.\n");
                    sr_arp_hdr_t* reply = (sr_arp_hdr_t*)malloc(sizeof(sr_arp_hdr_t));
                    /* TODO */
                    break;
                }
                iface = iface->next;
            }
        }
        else if (ar_op == arp_op_reply) {
        }

    }
    else if (ether_type == ethertype_ip) {
        printf("%s\n", "This is an IP packet.\n");
        int len_ether_ip = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        if (len < len_ether_ip) {
            fprintf(stderr, "Failed to handle packet, insufficient length.\n");
        }
    }

}/* end sr_ForwardPacket */

