#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include "enc_dec.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>


AES_KEY key; 

//unsigned char indata[SIZE]; 
//unsigned char outdata[SIZE];
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;

void init_ctr(struct ctr_state *state, const unsigned char iv[16])
{		 
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}


void init_iv() {
	
    if(!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        fprintf(stderr, "Could not create random bytes.");
        exit(1);    
    }
}


void error(unsigned char *msg)
{
    perror(msg);
    exit(1);
}


int set_non_block(int fd) {

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
        	error("error in fcntl\n");
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1)
		error("error in fcntl\n");
	return 1;
}

void print_key(unsigned char *key_buf) {
	int i=0;
	fprintf(stderr,"\n\nkey:\n");
	for (i=0; i < AES_BLOCK_SIZE; i++)
		printf("%x ", key_buf[i]);
	fprintf(stderr,"\nlen %d\n", i);
}
