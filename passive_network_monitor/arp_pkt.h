#ifndef ARP_PKT_H  
#define ARP_PKT_H

#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ARP_HEADER_LEN 28
//STRCPY AND HTONS NEEDED
#define ARP_REQ		1
#define ARP_RESP	2

struct arp_pkt {
	uint16_t hwtype;
	uint16_t prot_type;
	uint8_t hwa_len;
	uint8_t prota_len;
	uint16_t opc;
	uint8_t sha[6];
	uint8_t spa[4];
	uint8_t tha[6];
	uint8_t tpa[4];
};

#define ARP_GET_OPERATION(arp)		htons((arp)->opc)		
#define ARP_GET_PROT_TYPE(arp)		arp_get_prot_type((arp)->prot_type)
#define ARP_GET_SHA(arp)		arp_get_ha((arp)->sha)
#define ARP_GET_THA(arp)		arp_get_ha((arp)->tha)
#define ARP_GET_SPA(arp, src_addr)	arp_get_pa((arp)->spa,  (arp)->prot_type, src_addr)
#define ARP_GET_TPA(arp, dst_addr)	arp_get_pa((arp)->tpa,  (arp)->prot_type, dst_addr)

char* arp_get_prot_type(uint16_t prot_type) {
	prot_type = htons(prot_type);
	if(prot_type == 0x800)
		return "IPV4";
	else
		return "ARP_UNKNOWN_PROT";
}


char* arp_get_ha (uint8_t *addr) {
	return ether_ntoa((struct ether_addr*)addr);
}

void arp_get_pa (uint8_t *addr, uint16_t prot_type, char *ip_addr) {
	struct in_addr* prot_addr = (struct in_addr*)addr;
	prot_type = htons(prot_type);
	if(prot_type == 0x800) {
		strcpy(ip_addr, inet_ntoa(*prot_addr));
	}
	else
		strcpy(ip_addr, "IP_UNKNOWN_ADDR");
}
#endif /*ARP_PKT_H*/
