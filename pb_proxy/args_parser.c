#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

void parse_args(char* keyfile, char *dst_host, int *dst_port_num, int *pb_port_num, int argc, char *argv[], int *is_server) {

	char pb_port[16]="";
	char dst_port[16]="";
	int c=0, errflg=0;

	while ((c = getopt(argc, argv, "k:l:")) != -1) {
		switch(c) {
			case 'k':
				strcpy(keyfile, optarg);
				break;
			case 'l':
				strcpy(pb_port, optarg);
				break;
			default:
				printf("aborting\n");
				exit(2);
		}
	}


	printf(">>optind %d\n", optind);
	if(errflg) {
		printf("Uasge:\n");
		exit(2);
	}

	if (pb_port[0]){
		printf("is_server =1 and pb_port[0] %c", pb_port[0]);
		*is_server=1;
	}
	else {
		printf("is_server =0 and pb_port[0] %c", pb_port[0]);
		*is_server=0;
	}
	if ((optind + 2) != argc) {
		printf ("missing arguments\n");
		exit(2);

	}
	strcpy(dst_host, argv[optind++]);
	strcpy(dst_port, argv[optind++]);

	*pb_port_num = atoi(pb_port);
	*dst_port_num = atoi(dst_port);
}
