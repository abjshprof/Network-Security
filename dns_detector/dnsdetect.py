from scapy.all import *
import os
import sys
import os.path
import argparse

def dns_spoof_print(list1, bad_dns_seg):
        print("Spoof detected for", bad_dns_seg.id)
        print("names: ", [bad_dns_seg.an[i].rrname for i in range(0, bad_dns_seg.ancount) if bad_dns_seg.an[i].type == 0x1])
        print ("list1:", list1)
        print("list2:", [bad_dns_seg.an[i].rdata for i in range(0, bad_dns_seg.ancount) if bad_dns_seg.an[i].type == 0x1])

def dns_detect(packet):
        #print("Got packet")
        if DNS in packet and  packet[DNS].qr == 1 and packet[DNS].ancount > 0 and packet[DNS].qd[0].qtype == 0x1:
                #print("Got  s:",  packet[IP].src, "and dst ", packet[IP].dst, "host port", packet[UDP].sport, "id:", packet[DNS].id)
                if packet[DNS].id in answers:
                        if any (packet[DNS].an[i].rdata in answers[packet[DNS].id] for i in range(0, packet[DNS].ancount) if packet[DNS].an[i].type == 0x1):
                                print ("Common IP for ", packet[DNS].id, "not a spoof")
                        else:
                                dns_spoof_print(answers[packet[DNS].id], packet[DNS])
                else:
			answers[packet[DNS].id] = [packet[DNS].an[i].rdata for i in range(0, packet[DNS].ancount) if packet[DNS].an[i].type == 0x1]
			#for i in range(0, packet[DNS].ancount):
			#	if (packet[DNS].an[i].type == 0x1):
			#		answers[packet[DNS].id].append(packet[DNS].an[i].rdata)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i')
    parser.add_argument('-r')
    parser.add_argument('expression',nargs="*")
    args = parser.parse_args()
    read_offline = False
    #print(args)

    if args.i:
        interface = args.i
    else:
        interface = conf.iface

    print("Iface", interface)

    if args.r:
       trace_file = args.r
       print("Trace file", trace_file)
       read_offline = True

    global answers
    answers={}
    if args.expression:
       str1 = ' '.join(args.expression)
       pkt_filter = str1 + "and udp src port 53"
    else:
       pkt_filter = "udp src port 53"

    print("filter", pkt_filter)
    #test_fn()
    print("answers", answers)
    if(read_offline):
       print("reading offline")
       sniff(offline = trace_file, filter = pkt_filter, prn=dns_detect)
    else:
       sniff(iface=interface, filter=pkt_filter, count =0, prn=dns_detect)
