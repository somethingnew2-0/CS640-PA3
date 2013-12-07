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
#include <string.h>

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

uint16_t arpop(uint8_t *packet) {
        sr_arp_hdr_t *ahdr = (sr_arp_hdr_t *)packet;
        return ntohs(ahdr->ar_op);
}

uint16_t ip_cksum(uint8_t *buf) {
      sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
      return ntohs(iphdr->ip_sum);
}

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

    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) {
        fprintf(stderr , "Failed to parse ETHERNET header, insufficient length\n");
        return;
    }


    sr_ethernet_hdr_t* etherhdr = (sr_ethernet_hdr_t*)packet;
    uint16_t ethtype = ethertype(packet);

    if (ethtype == ethertype_ip) { /* IP */
        minlength += sizeof(sr_ip_hdr_t);
        if (len < minlength) {
            fprintf(stderr, "Failed to parse IP header, insufficient length\n");
            return;
        }

        /* Handle IP packet here */
        print_hdrs(packet, len);

        if (cksum(packet, len) != ip_cksum(packet + sizeof(sr_ethernet_hdr_t))) {
            fprintf(stderr , "Failed IP checksum, incorrect matchh\n");
            return;
        }

        uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        if (ip_proto == ip_protocol_icmp) { /* ICMP */
            minlength += sizeof(sr_icmp_hdr_t);
            if (len < minlength)
                fprintf(stderr, "Failed to parse ICMP header, insufficient length\n");
            /*else
             * Handle ICMP packet here */
        }
    }
    else if (ethtype == ethertype_arp) { /* ARP */
        minlength += sizeof(sr_arp_hdr_t);
        if (len < minlength) {
            fprintf(stderr, "Failed to parse ARP header, insufficient length\n");
        } else {
            /* Handle ARP packet here */
            print_hdrs(packet, len);

            uint16_t opcode = arpop(packet + sizeof(sr_ethernet_hdr_t));
            sr_arp_hdr_t* arphdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
            if (opcode == arp_op_request) {
                fprintf(stderr, "Who is ");
                print_addr_ip_int(ntohl(arphdr->ar_tip));

                printf("Packet interface: %s\n", interface);
                struct sr_if* iface = sr_get_interface(sr, interface);
                sr_print_if(iface);
                if(ntohl(iface->ip) == ntohl(arphdr->ar_tip)) {
                    fprintf(stderr, "Reply: I am!\n");

                    uint8_t tempetherhost[ETHER_ADDR_LEN];
                    memcpy(tempetherhost, etherhdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
                    memcpy(etherhdr->ether_dhost, etherhdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
                    memcpy(etherhdr->ether_shost, tempetherhost, sizeof(uint8_t) * ETHER_ADDR_LEN);

                    arphdr->ar_op = htons(arp_op_reply); 
                    arphdr->ar_tip = arphdr->ar_sip;
                    arphdr->ar_sip = htonl(iface->ip);
                    memcpy(arphdr->ar_tha, arphdr->ar_sha, sizeof(char) * ETHER_ADDR_LEN);
                    memcpy(arphdr->ar_sha, iface->addr, sizeof(char) * ETHER_ADDR_LEN);

                    print_hdrs(packet, len);

                    sr_send_packet(sr, packet, len, interface);
                }
            } else if (opcode == arp_op_reply) {
                fprintf(stderr, "I am ");
                print_addr_eth(arphdr->ar_tha);
            } else {
                fprintf(stderr, "Unrecognized Arp Opcode: %d\n", opcode);
            }
        }
    }
    else {
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }


}/* end sr_ForwardPacket */

