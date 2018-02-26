#ifndef UDP_PKT_H
#define UDP_PKT_H
#define UDP_HEADER_LEN 8
#include <stdint.h>
struct udpheader {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len; /*sum of ip_data_len + udp_data_len*/
	uint16_t	check;
};

#define UDP_GET_SRC_PORT(udp)		htons(((udp)->source))
#define UDP_GET_DST_PORT(udp)		htons(((udp)->dest))
#define UDP_GET_DATA_LEN(udp)		htons((((udp)->len) - 8))
#define UDP_GET_TOTAL_LEN(udp)		htons((((udp)->len)))

#endif /*UDP_PKT_H*/

