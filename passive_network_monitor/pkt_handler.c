#include <stdio.h>
#include <pcap.h>
#include <sys/time.h>
#include <ctype.h>
#include <time.h>
#include "eth_pkt.h"
#include "ip_pkt.h"
#include "udp_pkt.h"
#include "arp_pkt.h"
#include "icmp_pkt.h"
#include "tcp_pkt.h"
#include "mystrstr.h"

int pkt_cnt =1;
void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int tot_len = header->len, i, pld_start;
	int cap_pkt_len = header->caplen;
	struct eth_header* eth_hdr;
	struct arp_pkt* arp_hdr;
	struct ip_header* ip_hdr;
	struct tcp_header* tcp_hdr;
	struct icmpheader* icmp_hdr;
	struct udpheader* udp_hdr;
	unsigned char *payload;
	int ip_hl, tcp_hl, src_port, dst_port;
	int eth_type;
	int ip_prot;
	char ethtype_str[18];
	char src_mac_addr[18];
	char dst_mac_addr[18];
	char src_ip_addr[18];
	char dst_ip_addr[18];
	char ip_prot_type[18];
	void *found;

	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];

	//printf("pkt_cnt %d\n", pkt_cnt++);

	tv=header->ts;
	nowtime = tv.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);

	eth_hdr = (struct eth_header*)(packet);
	eth_type = htons(eth_hdr->ether_type);

	ip_hdr = (struct ip_header*)(packet + SIZE_ETHERNET);
	if (eth_type == IPV4) {
		if ((IP_V(ip_hdr)) != 4) {
			printf("not and IPV4 pkt\n");
			return;
		}
		ip_prot=ip_hdr->ip_p;
		ip_hl = IP_HL(ip_hdr);;
		if (ip_hl < 20) {
			printf("   * Invalid IP header length: %u bytes\n", ip_hl);
			return;
		}
		IP_SRC_ADDR(ip_hdr, src_ip_addr);
		IP_DST_ADDR(ip_hdr, dst_ip_addr);
		IP_GET_PROTOCOL(ip_hdr, ip_prot_type);

		if(ip_prot == TCP){
			tcp_hdr = (struct tcp_header*)(packet + ip_hl + SIZE_ETHERNET);
			src_port = TCP_GET_SRC_PORT(tcp_hdr);
			dst_port = TCP_GET_DST_PORT(tcp_hdr);
			tcp_hl = TCP_GET_HEADER_LEN(tcp_hdr);
			payload = (unsigned char *)(packet + SIZE_ETHERNET + ip_hl + tcp_hl);
			pld_start = SIZE_ETHERNET + ip_hl + tcp_hl;
		}
		else if (ip_prot == UDP) {
			udp_hdr = (struct udpheader*)(packet + ip_hl + SIZE_ETHERNET);
			src_port = UDP_GET_SRC_PORT(udp_hdr);
			dst_port = UDP_GET_DST_PORT(udp_hdr);
			payload = (unsigned char *)(packet + SIZE_ETHERNET + ip_hl + UDP_HEADER_LEN);
			pld_start = SIZE_ETHERNET + ip_hl + UDP_HEADER_LEN;
		}
		else if (ip_prot == ICMP) {
			icmp_hdr = (struct icmpheader*)(packet + ip_hl + SIZE_ETHERNET);
			payload = (unsigned char *)(packet + SIZE_ETHERNET + ip_hl + ICMP_HEADER_LEN);
			pld_start = SIZE_ETHERNET + ip_hl + ICMP_HEADER_LEN;
		}
		else if (ip_prot == IGMP) {
			payload = (unsigned char *)(packet + SIZE_ETHERNET + ip_hl + 8);
			pld_start = SIZE_ETHERNET + ip_hl + 8;
		}
		else {
			//printf("IP_UNKNOWN");
			payload = (unsigned char *)(packet + SIZE_ETHERNET + ip_hl + 8);
			pld_start = SIZE_ETHERNET + ip_hl + 8;
		}
	}
	else if (eth_type == ARP) {
		arp_hdr = (struct arp_pkt*)(packet + SIZE_ETHERNET);
		ARP_GET_SPA(arp_hdr, src_ip_addr);
		ARP_GET_TPA(arp_hdr, dst_ip_addr);
		payload = (unsigned char *)(packet + SIZE_ETHERNET + ARP_HEADER_LEN);
		pld_start = SIZE_ETHERNET + ARP_HEADER_LEN;
	}
	else{
		//printf("Unknown packet\n");
		payload = (unsigned char *)(packet + SIZE_ETHERNET);
		pld_start = SIZE_ETHERNET;
		//return;
	}

	found = mymemmem(payload, cap_pkt_len - pld_start, args, strlen(args));
	if (found) {
		EHT_GET_TYPE(eth_hdr, ethtype_str);
		ETH_GET_SRC_MAC(eth_hdr, src_mac_addr);
		ETH_GET_DST_MAC(eth_hdr, dst_mac_addr);

		printf("%s %s -> %s type %s len %d\n",buf, src_mac_addr, dst_mac_addr, ethtype_str, cap_pkt_len);
		if (eth_type == IPV4) {
			if(ip_prot == TCP || ip_prot == UDP){
				printf("%s.%d -> %s.%d ", src_ip_addr, src_port, dst_ip_addr, dst_port);
			}
			else if (ip_prot == ICMP) {
				printf("%s -> %s ", src_ip_addr, dst_ip_addr);
			}
			else if (ip_prot == IGMP){
				//printf("IGMP");
			}
			
			printf("%s\n", ip_prot_type);
		}
		else if (eth_type == ARP) {
			if (ARP_GET_OPERATION(arp_hdr) == ARP_REQ)
				printf("ARP Request who-has %s tell %s\n", dst_ip_addr, src_ip_addr);
			else
				printf("ARP Response: %s-> %s \n", src_ip_addr, dst_ip_addr);
		}
		else{
			//printf("NOT an IP_PACKET \n");
		}
		for (i=pld_start; i< cap_pkt_len; i++) {
			if (isprint(packet[i])) {
				printf("%c", packet[i]);
			} else {
				printf(".");
			}
		}
	printf("\n\n");
	}
}
