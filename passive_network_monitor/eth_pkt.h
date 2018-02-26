#ifndef ETH_PKT_H
#define ETH_PKT_H

#include <netinet/ether.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/types.h>

#define SIZE_ETHERNET 14
//#define ETHER_ADDR_LEN	6
//if ether type > 1536, it is ether type
//if <= 1500 , it is size of the payload


char *get_eth_addr(u_char* ethaddr, char* mac) {
	snprintf(mac, 16, "%02x:%02x:%02x:%02x:%02x:%02x", ethaddr[0], ethaddr[1], ethaddr[2], ethaddr[3], ethaddr[4], ethaddr[5]);
}
#define IPV4	0x800
#define ARP  	0x806
#define IPV6	0x86dd
#define LLDP	0x88cc
#define RARP	0x8035

char* get_ether_type(uint16_t ether_type, char*eth_type)
{

	ether_type = htons(ether_type);
	//printf("ether_type %x\n", ether_type);
	if (ether_type <= 1500)
		//return "LEN_FIELD";
		strcpy(eth_type, "LEN_FIELD");
	switch(ether_type) {
		case 0x800:
			//return "IPv4";
			strcpy(eth_type,"IPv4");
			break;
		case 0x806:
			//return "ARP";
			strcpy(eth_type, "ARP");
			break;
		case 0x86dd:
			//return "IPV6";
			strcpy(eth_type, "IPV6");
			break;
		case 0x88cc:
			//return "LLDP";
			strcpy(eth_type, "LLDP");
			break;
		case 0x8035:
			//return "RARP";
			strcpy(eth_type, "RARP");
			break;
		default:
			//return "UNKOWN_ETH_TYPE";
			strcpy(eth_type, "UNKNOWN_ETH_TYPE");
	}
}

struct eth_header {
	u_char ether_dhost[6]; /* Destination host address */
	u_char ether_shost[6]; /* Source host address */
	__be16 ether_type; /* IP? ARP? RARP? etc */
}__attribute__((packed));

#define EHT_GET_TYPE(eth_hdr, eth_type)		get_ether_type(((eth_hdr)->ether_type), eth_type)
#define ETH_GET_SRC_MAC(eth_hdr, src_mac)	get_eth_addr((eth_hdr)->ether_shost, src_mac)
#define ETH_GET_DST_MAC(eth_hdr, dst_mac)	get_eth_addr((eth_hdr)->ether_dhost, dst_mac)



#endif /*ETH_PKT_H*/
