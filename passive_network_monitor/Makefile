all: pkt_handler.o test_pcap.o
	gcc -o mydump test_pcap.o pkt_handler.o  -lpcap
	./mydump -h
run:
	./mydump

clean:
	rm -f mydump test_pcap.o pkt_handler.o
