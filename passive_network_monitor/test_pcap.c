#include <stdio.h>
#include <ctype.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int isalphanumeric(const char *str) {
	int i=0;
	while(str[i]) {
		if(isalnum(str[i++])){
			continue;
		}
		else
			return 0;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int i, c, errflg=0;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	u_char *user;
	char dev[16]="";
	char filename[16]="";
	char str[16]="";
	char *tmp_optarg;
	char *final_dev;
	pcap_t *handle;
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[16];	/* The filter expression */
	bpf_u_int32 mask=0;		/* The netmask of our sniffing device */
	bpf_u_int32 net=0;		/* The IP of our sniffing device */


	final_dev=dev;
	user = str;

	while ((c = getopt(argc, argv, "hs::i::r:")) != -1) {
		tmp_optarg=NULL;
		switch(c) {
			case 'i':
				if (!optarg && (NULL != argv[optind]) && ('-' != argv[optind][0]) && (optind < argc)) {
					tmp_optarg = argv[optind++];
				}
				if (tmp_optarg) {
					strcpy(dev, tmp_optarg);
				}
				break;
			case 'r':
				if(*optarg == '-') {
					errflg++;
				}
				else
					strcpy(filename, optarg);
				break;
			case 's':
				if (!optarg && (NULL != argv[optind]) && ('-' != argv[optind][0]) && (optind < argc)) {
					tmp_optarg = argv[optind++];
				}
				if (tmp_optarg) {
					strcpy(str, tmp_optarg);
				}
				break;
			case 'h':
				printf("Usage: ./test_pcap -i <eth interface> -s <str> -r<filename>  \"bpf expression\"\n");
				exit(0);
				break;
			case '?':
				if (optopt == 'r') {
					printf("Option %c requires an argument, filename\n", optopt);
					errflg++;
				}
				else {
					printf("Unkown option character %c\n", optopt);
					errflg++;
				}
				break;
			default:
				printf("aborting\n");
				exit(2);
		}
	}


	if((optind < argc) && argv[optind]) {
		i=0;
		if((optind + 1 ) == argc) {
			strcpy(filter_exp, argv[optind]);
		}
		else {
			while(optind < argc) {
				strcpy(filter_exp+i, argv[optind]);
				i += strlen(argv[optind]);
				strcpy(filter_exp+i," ");
				i++;
				optind++;
			}
			filter_exp[i-1]=0;
		}
	}

	if(errflg) {
		printf("Usage: ./test_pcap -i <eth interface> -s <str> -r<filename>  \"bpf expression\"\n");
		exit(2);
	}

	printf("\nOptions passed:\n  Device:  %s\n  Filename: %s\n  str to match: %s\n  filter_exp: %s\n", final_dev, filename, str, filter_exp);
	if(!str[0])
		printf("\nNULL string passed: we will match everything\n");


	if (filename[0]) {
		handle = pcap_open_offline(filename, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
			return(2);
		}
	}
	else {
		if((final_dev && !final_dev[0]) || !isalphanumeric(final_dev)) { //sequence of checking matters
			printf("\nDevice name passed is null or not alphanumeric, trying default device\n");
			final_dev = pcap_lookupdev(errbuf);
			if (final_dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
				return(2);
			}
			else
				printf("\nGot dev %s as default\n", final_dev);
		}

		if (pcap_lookupnet(final_dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", final_dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */

		handle = pcap_open_live(final_dev, 65535, 1, 5000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", final_dev, errbuf);
			return(2);
		}

		printf("\nSniffing on %s\n", final_dev);

		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", final_dev);
			return(2);
		}
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	printf("\n===============================\n\n");
	pcap_loop(handle, -1, pkt_handler, user);

	pcap_close(handle);

	return(0);
}
