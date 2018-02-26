#ifndef ENC_DEC
#define ENC_DEC
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define SIZE 4096
struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}; 



AES_KEY key; 

unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;
/*
extern AES_KEY key;
extern struct ctr_state state;
extern unsigned char iv[AES_BLOCK_SIZE];
*/

void init_ctr(struct ctr_state *state, const unsigned char iv[16]);

void init_iv();


void error(unsigned char *msg);

int set_non_block(int fd);

void print_key(unsigned char *key_buf);


#endif
