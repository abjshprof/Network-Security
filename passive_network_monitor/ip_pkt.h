#ifndef IP_PKT_H
#define IP_PKT_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>

//print a warning when ip_hl > 5
struct ip_header {
	u_char ip_vhl;//0		/* version << 4 | header length >> 2 */
	u_char ip_tos;//1		/* type of service */
	u_short ip_len;//2-3		/* total length (including header and data)*/
	u_short ip_id;//4-5		/* identification */
	u_short ip_off;//6-7		/* fragment offset field and flags */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;//8		/* time to live */
	u_char ip_p;//9		/* protocol */
	u_short ip_chksum;//10-11		/* checksum */
	struct in_addr ip_src;//12-15
	struct in_addr ip_dst;//16-19  	/* source and dest address */
	//include padding and options here??
};

//get ip header fields

#define IP_HL(ip)			(((ip)->ip_vhl) & 0x0f)*4
#define IP_V(ip)			(((ip)->ip_vhl) >> 4)
#define IP_TOTAL_LEN(ip)		htons((((ip)->ip_len)))
#define IP_DATA_LEN(ip)			htons((((ip)->ip_len) - 20))
#define IP_FRAG_OFF(ip)			htons((((ip)->ip_off) & 0x1fff))
#define IP_IS_FRAG(ip)			(htons(((ip)->ip_off)) & IP_MF)
#define IP_GET_TTL(ip)			(((ip)->ip_ttl))
#define IP_GET_PROTOCOL(ip, prot) 	ip_get_protocol(((ip)->ip_p), prot)
#define IP_CHKSUM(ip)			(((ip)->ip_chksum))
//conversion required
#define IP_SRC_ADDR(ip, src_addr)	ip_get_addr((((ip)->ip_src)), src_addr)
#define IP_DST_ADDR(ip, dst_addr)	ip_get_addr((((ip)->ip_dst)), dst_addr)

void ip_get_addr(struct in_addr addr, char* ip_addr){
    strcpy(ip_addr, inet_ntoa(addr));
}


#define ICMP	0x01
#define IGMP	0x02
#define TCP	0x06
#define UDP	0x11

void ip_get_protocol(u_char prot_f, char *prot)
{
	switch(prot_f) {
		case 0x01:
			//return "ICMP";
			strcpy(prot, "ICMP");
			break;
		case 0x02:
			//return "IGMP";
			strcpy(prot, "IGMP");
			break;
		case 0x06:
			//return "TCP";
			strcpy(prot, "TCP");
			break;
		case 0x11:
			//return "UDP";
			strcpy(prot, "UDP");
			break;
		default :
			//return "IP_UNKNOWN";
			strcpy(prot, "IP_UNKNOWN");
	}
}
#endif /*IP_PKT_H*/
