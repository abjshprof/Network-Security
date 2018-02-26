#ifndef TCP_PKT_H
#define TCP_PKT_H

#include <pcap.h>
typedef u_int tcp_seq;
struct tcp_header {
	u_short src_port;	/* source port */
	u_short dst_port;	/* destination port */
	tcp_seq tcp_seq;		/* sequence number */
	tcp_seq tc_ack;		/* acknowledgement number */
	u_char tcp_offx2;	/* data offset, rsvd */
	u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short tcp_win;		/* window */
	u_short tcp_sum;		/* checksum */
	u_short tcp_urp;		/* urgent pointer */
};

#define TCP_GET_HEADER_LEN(tcp_hdr)		((((tcp_hdr)->tcp_offx2) & 0xf0) >> 4)*4
#define TCP_GET_FLAG(tcp_hdr)			tcp_get_flag(((tcp_hdr)->tcp_flags))
#define TCP_GET_SRC_PORT(tcp_hdr)		htons(((tcp_hdr)->src_port))
#define TCP_GET_DST_PORT(tcp_hdr)		htons(((tcp_hdr)->dst_port))


#endif /*TCP_PKT_H*/
