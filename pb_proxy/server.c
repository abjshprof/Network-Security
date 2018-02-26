/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include "enc_dec.h"


void handle_connection(int cli_sockfd, unsigned char* dst_host, int dst_port_num, unsigned char *keyfile) {

	unsigned char buffer_send[SIZE];
	int readc, writec, keyfd;
	int dst_sockfd, count =0;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	unsigned char buffer_recv[SIZE], key_buf[AES_BLOCK_SIZE];

	//printf("trying to open %s", keyfile);
	if ((keyfd = open(keyfile, O_RDWR)) == -1) {
		printf("error opening file %s\n", keyfile);
		exit(2);
	}
	if (read(keyfd, key_buf, AES_BLOCK_SIZE)< 0) {
		printf("error occured\n");
		exit(2);		
	}
	close(keyfd);
	//print_key(key_buf);

	dst_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (dst_sockfd < 0) 
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

	//printf("IP addr %s and %llx and len %d\n", (server->h_name), INADDR_ANY, server->h_length);
	//printf("%s\n", key_buf);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(dst_port_num);
	//printf("trying to connect to port %d\n", dst_port_num);
	if (connect(dst_sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
		error("ERROR connecting");

	//printf(">>sucessfully connected and AES_BLOCK_SIZE %d\n", AES_BLOCK_SIZE);



	set_non_block(cli_sockfd);
	set_non_block(dst_sockfd);

	count=0;
	
	while(1) {
		readc = read(cli_sockfd, iv, AES_BLOCK_SIZE);
		count += readc;
		//if (readc > 0)
			//fprintf(stderr, "%s and readc %d and count %d\n", iv, readc, count);
		if (count >= AES_BLOCK_SIZE)
			break;
	}
	
	//fprintf(stderr, "Done %s\n", iv);


	if (AES_set_encrypt_key(key_buf, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set encryption key.");
		exit(1);
	}
	init_ctr(&state, iv);
	//fprintf(stderr, "iv: %s\n", iv);

	//fprintf(stderr, "Key stuff done\n");
	while(1) {
		//fprintf(stderr, "First try\n");
		while((readc = read(cli_sockfd, buffer_recv, SIZE)) > 0) {
			//readc = read(cli_sockfd, buffer_recv, SIZE);
			if(readc == 0){
				close(cli_sockfd);
				close(dst_sockfd);
				fprintf(stderr, "closed connection");
				exit(0);
			}
			unsigned char send1[SIZE];
			AES_ctr128_encrypt(buffer_recv, send1, readc, &key, state.ivec, state.ecount, &state.num);
			writec = write(dst_sockfd, send1, readc);
			//usleep(900);
			//fprintf(stderr, "received %s\n", indata);
			if (readc < SIZE)
				break;
		}
		//fprintf(stderr, "Out of loop\n");
		readc=0;
		usleep(9000);
		while((readc = read(dst_sockfd, buffer_send, SIZE)) > 0) {
			//fprintf(stderr, "trying to read\n");
			//readc = read(dst_sockfd, buffer_send, SIZE);
			unsigned char recv1[SIZE];
			AES_ctr128_encrypt(buffer_send, recv1, readc, &key, state.ivec, state.ecount, &state.num);
			//fprintf(stderr, "writing %s\n", recv1);
			writec = write(cli_sockfd, recv1, readc);
			//usleep(900);
			if (readc < SIZE)
				break;
		}
	}
	
}



int server(unsigned char *keyfile, unsigned char *dst_host, int dst_port_num, int pb_port_num)
{

	//parse_args(keyfile, dst_host, &dst_port_num, &pb_port_num, argc, argv, &is_server);
	int sockfd, cli_sockfd;
	socklen_t clilen;
	printf("pb_port %d\n", pb_port_num);
	printf("key file %s\n", keyfile);
	printf("dst_host %s\n", dst_host);
	printf("dst_port %d\n", dst_port_num);
	
	struct sockaddr_in serv_addr, cli_addr;
	int pid;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");
	bzero((unsigned char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(pb_port_num);
	if (bind(sockfd, (struct sockaddr *) &serv_addr,
		sizeof(serv_addr)) < 0) 
		error("ERROR on binding");
	listen(sockfd,50);
	clilen = sizeof(cli_addr);

	while(1) {
		cli_sockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		//printf ("Got a connection from %s", (cli_addr.sin_addr).s_addr);
		if (cli_sockfd < 0) 
			error("ERROR on accept");
		pid=fork();
		if (pid < 0)
			error("ERROR on fork");
		if (pid == 0) {
			close (sockfd);
			handle_connection(cli_sockfd, dst_host, dst_port_num, keyfile);
			exit(0);
		}
		else
			close(cli_sockfd);
	}
}
