#include <stdio.h>
extern void parse_args(unsigned char* keyfile, unsigned char *dst_host, int *dst_port_num, int *pb_port_num, int argc, char *argv[], int *server);

extern int server( unsigned char *keyfile,  unsigned char *dst_host, int dst_port_num, int pb_port_num);
extern int client( unsigned char *keyfile,  unsigned char *dst_host, int dst_port_num, int pb_port_num);

int main(int argc, char *argv[])
{
	unsigned char keyfile[16]="";
	unsigned char dst_host[16] = "";
	int dst_port_num, pb_port_num, is_server;


	parse_args(keyfile, dst_host, &dst_port_num, &pb_port_num, argc, argv, &is_server);

	if (is_server) {
		printf("calling server code\n");
		server(keyfile, dst_host, dst_port_num, pb_port_num);
	}
	else {
		printf("calling client code\n");
		client(keyfile, dst_host, dst_port_num, pb_port_num);
	}
}
