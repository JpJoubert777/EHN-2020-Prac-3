
#include "RC4.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

void rc4_init(rc4ctx_t* rc4c, unsigned char * key, int keylen)
{

	unsigned char temp; //used for the swapping 
	unsigned char T[256]; //temporary storage for key operations
	// Initialization
	for (int i = 0; i < 256; i++)
	{
		rc4c->S[i] = i;
		T[i] = key[i % keylen];
	}
	//initial permutation of S
	int j = 0;
	for (int i = 0; i < 256; i++)
	{
		j = (j + rc4c->S[i] + T[i]) % 256;
		// swap S[i] and S[j]
		temp = rc4c->S[i];
		rc4c->S[i] = rc4c->S[j];
		rc4c->S[j] = temp;
	}
	//initial context values
	rc4c->i = 0;
	rc4c->j = 0;
}

unsigned char  rc4_getByte(rc4ctx_t* rc4c)
{
	unsigned char temp; //used for the swapping
	unsigned char t; //temporary indexing variable
	unsigned char k; //will be the returned byte 

	rc4c->i = (rc4c->i + 1) % 256;
	rc4c->j = (rc4c->j + rc4c->S[rc4c->i]) % 256;
	// swap S[i] and S[j]
	temp = rc4c->S[rc4c->i];
	rc4c->S[rc4c->i] = rc4c->S[rc4c->j];
	rc4c->S[rc4c->j] = temp;
	t = (rc4c->S[rc4c->i] + rc4c->S[rc4c->j]) % 256;
	k = rc4c->S[t];
	return k;
	
}

void generateStream(unsigned char * RC4Stream, int numPlaintextBytes,rc4ctx_t* rc4Context)
{
	
	printf("\nRC4 stream: \n");
	for (int i = 0; i < numPlaintextBytes; i++)
	{ 
		RC4Stream[i] = rc4_getByte(rc4Context);
		printf("%02x ",RC4Stream[i]);
	}
	printf("\n");

}
void RC4Encrypt(unsigned char * plainText,unsigned char * cypherText,int numPlaintextBytes, unsigned char * key, int keyLength)
{
	unsigned char * RC4Stream;
	
	rc4ctx_t rc4Context;

	RC4Stream = malloc(numPlaintextBytes +1);
	rc4_init(&rc4Context,key,keyLength);
	generateStream(RC4Stream,numPlaintextBytes,&rc4Context);

	printf("\nPlainText:\n");
	for (int i = 0; i < numPlaintextBytes; i ++)
	{
		printf("%c",plainText[i]);
	}
	printf("\n");

	printf("\nRC4 Encrypt: \n");
	for (int x = 0; x < numPlaintextBytes; x++)
	{
		cypherText[x] = plainText[x] ^ RC4Stream[x];
		printf("%02x ",cypherText[x]);
	}
	printf("\n\n");
}

void RC4Decrypt(unsigned char * plainText,unsigned char * cypherText,int numPlaintextBytes, unsigned char * key, int keyLength)
{
	unsigned char * RC4Stream;
	
	rc4ctx_t rc4Context;

	RC4Stream = malloc(numPlaintextBytes +1);
	rc4_init(&rc4Context,key,keyLength);
	generateStream(RC4Stream,numPlaintextBytes,&rc4Context);

	printf("\nRC4 Decrypt: \n");
	for (int x = 0; x < numPlaintextBytes; x++)
	{
		plainText[x] = cypherText[x] ^ RC4Stream[x];
		printf("%c ",plainText[x]);
	}
	printf("\n\n");
}

