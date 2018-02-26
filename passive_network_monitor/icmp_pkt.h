#ifndef ICMP_PKT_H
#define ICMP_PKT_H
#include <stdint.h>
//The ICMP header starts after the IPv4 header
#define ICMP_HEADER_LEN	8
struct icmpheader {
	uint8_t	 type;
	uint8_t	 code;
	uint16_t checksum;
  union {
	struct {
		uint16_t id;
		uint16_t sequence;
	} echo;
	uint32_t gateway;
	struct {
		uint16_t __unused;
		uint16_t mtu;
	} frag;
	uint8_t	reserved[4];
  } un;
};

//what will be the data?/

#endif /*ICMP_PKT_H*/
