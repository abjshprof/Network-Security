#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "enc_dec.h"


int client(unsigned char *keyfile, unsigned char *dst_host, int dst_port_num, int pb_port_num)
{

	int sockfd, readc, writec, count, flags, keyfd;

	struct sockaddr_in serv_addr;
	struct hostent *server;

	unsigned char buffer_send[SIZE];
	unsigned char buffer_recv[SIZE], key_buf[AES_BLOCK_SIZE];
	//unsigned char recv1[SIZE];
	//unsigned char send1[SIZE];

	printf(">>here\n");
	printf("in client and keyfile %s and dst_host %s dst_port_num %d pb_port_num %d\n", keyfile, dst_host, dst_port_num, pb_port_num);

	if ((keyfd = open(keyfile, O_RDWR)) == -1) {
		printf("error opening file %s\n", keyfile);
		exit(2);
	}
	if (read(keyfd, key_buf, AES_BLOCK_SIZE)< 0) {
		printf("error occured\n");
		exit(2);		
	}

	close(keyfd);
	printf("done readinf\n");

	//print_key(key_buf);
	//sleep(2);
	//fprintf(stderr, "dst_port_num %d and dst_host %s\n", dst_port_num, dst_host);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	
	if (sockfd < 0) 
		error("ERROR opening socket");
	bzero((unsigned char *) &serv_addr, sizeof(serv_addr));
	server = gethostbyname(dst_host);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bcopy((unsigned char *)server->h_addr, 
	     (unsigned char *)&serv_addr.sin_addr.s_addr,
	     server->h_length);

	//fprintf(stderr, "IP addr %s and INADDR %llx and len %d\n", (server->h_name), INADDR_ANY, server->h_length);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(dst_port_num);
	if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
		error("ERROR connecting");
	//fprintf(stderr, "Connected\n");

	//fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	//fcntl(sockfd, F_SETFL, O_NONBLOCK);
	set_non_block(sockfd);
	set_non_block(STDIN_FILENO);
	set_non_block(STDOUT_FILENO);

	init_iv();
	if (AES_set_encrypt_key(key_buf, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set encryption key.");
		exit(1);
	}
	init_ctr(&state, iv);

	//fprintf(stderr, "%s\n", iv);
	//fprintf(stderr, "writing and iv %s\n", iv);
	count = 0;
	
	while (1) {
		writec = write(sockfd, iv, AES_BLOCK_SIZE);
		//usleep(900);
		count+=writec;
		if  (count >= AES_BLOCK_SIZE)
			break;
	}
	
	//fprintf(stderr, "Done\n");
	while(1) {
		count=0;

		while((readc = read(STDIN_FILENO, buffer_send, SIZE)) > 0) {
			//fprintf(stderr,"trying to read\n");
			//readc = read(STDIN_FILENO, buffer_send, SIZE);
			unsigned char send1[readc];
			AES_ctr128_encrypt(buffer_send, send1, readc, &key, state.ivec, state.ecount, &state.num);
			writec = write(sockfd, send1, readc);
			//usleep(900);
			//fprintf(stderr, "sent buffer_send %s\n", buffer_send);
			if (readc < SIZE)
				break;
		}
		usleep(9000);
		readc=0;
		while((readc = read(sockfd, buffer_recv, SIZE)) > 0) {
			//fprintf(stderr,"checking\n");
			//readc = read(sockfd, buffer_recv, SIZE);
			//fprintf(stderr, "recevied2 %s\n", buffer_recv);
			unsigned char recv1[readc];
			AES_ctr128_encrypt(buffer_recv, recv1, readc, &key, state.ivec, state.ecount, &state.num);
			//fprintf(stderr, "decrypt %s\n", recv1);
			writec = write(STDOUT_FILENO, recv1, readc);
			//usleep(900);
			//fprintf(stderr, "write2 %s\n", recv1);
			if (readc < SIZE)
				break;
		}
		count=0;
	}
	return 0;
}
