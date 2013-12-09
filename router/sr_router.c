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
#include <stdlib.h> 
#include <assert.h>
#include <string.h>
#include <limits.h>

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

    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) {
        fprintf(stderr , "Failed to parse ETHERNET header, insufficient length\n");
        return;
    }


    struct sr_if* iniface = sr_get_interface(sr, interface);
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
        
        sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        uint16_t ipsum = iphdr->ip_sum;
        iphdr->ip_sum = 0;

        if (cksum(iphdr, sizeof(sr_ip_hdr_t)) != ipsum) {
            fprintf(stderr , "Failed IP checksum, incorrect match\n");
            return;
        } else {
            iphdr->ip_sum = ipsum;
        }
        if (ntohl(iphdr->ip_dst) == ntohl(iniface->ip)) {
            uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
            if (ip_proto == ip_protocol_icmp) { /* ICMP */
                minlength += sizeof(sr_icmp_hdr_t);
                if (len < minlength) {
                    fprintf(stderr, "Failed to parse ICMP header, insufficient length\n");
                    return;
                }
                else {
                    /* Handle ICMP packet here */
                    sr_icmp_hdr_t* icmphdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                    uint16_t icmpsum = icmphdr->icmp_sum;
                    icmphdr->icmp_sum = 0;
                    
                    if (cksum(icmphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)) != icmpsum) {
                        fprintf(stderr , "Failed ICMP checksum, incorrect match %d %d\n", cksum(icmphdr, sizeof(sr_icmp_hdr_t)), icmpsum);
                        return;
                    }

                    if(icmphdr->icmp_type == 8) {
		      memcpy(etherhdr->ether_dhost, etherhdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
		      memcpy(etherhdr->ether_shost, iniface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
		      uint32_t src = iphdr->ip_src;
		      iphdr->ip_src = iphdr->ip_dst;
		      iphdr->ip_dst = src;
		      iphdr->ip_sum = 0;
		      iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

		      icmphdr->icmp_type = 0;
		      icmphdr->icmp_code = 0;
		      icmphdr->icmp_sum = 0;
		      icmphdr->icmp_sum = cksum(icmphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		      
		      print_hdrs(packet, len);
		      sr_send_packet(sr, packet, len, iniface->name);
		    }
		    else {
                        fprintf(stderr, "Ignoring this ICMP message %d\n", icmphdr->icmp_type);
                    }
                }
            }
        } else {
            /* Decrement TTL on ip header */
            iphdr->ip_ttl--;
            /* Recompute checksum */
            iphdr->ip_sum = 0;
            iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

            /* Find interface with longest prefix match for ip destination to forward to */
            struct sr_rt* rt_match = NULL;
            struct sr_rt* rt_walker = sr->routing_table;

            while(rt_walker) {
                uint32_t prefix = (iphdr->ip_dst & (*(uint32_t*)&rt_walker->mask)) - (*(uint32_t*)&rt_walker->dest);
                if(prefix  == 0) { 
                    rt_match = rt_walker;
                    break;
                }
                rt_walker = rt_walker->next;
            }

            if(rt_match == NULL) {
                /* send icmp type 3 code 0 reponse */
                return;
            }

            struct sr_if* outiface = sr_get_interface(sr, rt_match->interface);

            /* Sending packet to next hop ip */
            struct sr_arpentry* arpentry = sr_arpcache_lookup(&sr->cache, iphdr->ip_dst); 
            if (arpentry) {
                /*use next_hop_ip->mac mapping in entry to send the packet */
                memcpy(etherhdr->ether_dhost, arpentry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
                memcpy(etherhdr->ether_shost, outiface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
                
                sr_send_packet(sr, packet, len, outiface->name);

                free(arpentry);
            } else {
                struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, iphdr->ip_dst, packet, len, outiface->name, iniface->name);
                handle_arpreq(sr, req);
            }
        }

        print_hdrs(packet, len);

    }
    else if (ethtype == ethertype_arp) { /* ARP */
        minlength += sizeof(sr_arp_hdr_t);
        if (len < minlength) {
            fprintf(stderr, "Failed to parse ARP header, insufficient length\n");
        } else {
            /* Handle ARP packet here */
            print_hdrs(packet, len); 

            sr_arp_hdr_t* arphdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
            switch (ntohs(arphdr->ar_op)) {
            case arp_op_request:
                fprintf(stderr, "Who is ");
                print_addr_ip_int(ntohl(arphdr->ar_tip));

                /* printf("Packet interface: %s\n", interface); */
                /* sr_print_if(iface); */

                /* ARP request for router */
                if(ntohl(iniface->ip) == ntohl(arphdr->ar_tip)) {
                    /* Respond to ARP request */
                    fprintf(stderr, "Reply: I am!\n");

                    memcpy(etherhdr->ether_dhost, etherhdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
                    memcpy(etherhdr->ether_shost, iniface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

                    arphdr->ar_op = htons(arp_op_reply); 
                    arphdr->ar_tip = arphdr->ar_sip;
                    arphdr->ar_sip = iniface->ip;
                    memcpy(arphdr->ar_tha, arphdr->ar_sha, sizeof(char) * ETHER_ADDR_LEN);
                    memcpy(arphdr->ar_sha, iniface->addr, sizeof(char) * ETHER_ADDR_LEN);

                    print_hdrs(packet, len); 

                    sr_send_packet(sr, packet, len, interface);
                }
                /* ARP request for some other address */
                else {
                    /* Pass along ARP request */
                }
                break;
            case arp_op_reply:
                fprintf(stderr, "I am ");
                print_addr_eth(arphdr->ar_sha);
                
                struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip);
                if (req) {
                     /* send all packets on the req->packets linked list */
                     struct sr_packet* pkt = req->packets;
                     struct sr_packet* nextPkt;
        		     while(pkt) {
		                  nextPkt = pkt->next;
		                 sr_ethernet_hdr_t* newetherhdr = (sr_ethernet_hdr_t*)(pkt->buf);
                         memcpy(newetherhdr->ether_dhost, arphdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
                         memcpy(newetherhdr->ether_shost, arphdr->ar_tha, sizeof(uint8_t) * ETHER_ADDR_LEN);

                         print_hdrs(pkt->buf, pkt->len);

                         sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                         pkt = nextPkt;
                     }
                     sr_arpreq_destroy(&sr->cache, req);
                }
                break;
            default:
                fprintf(stderr, "Unrecognized Arp Opcode: %d\n", ntohs(arphdr->ar_op));
                break;
            }
        }
    }
    else {
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }


}/* end sr_ForwardPacket */

