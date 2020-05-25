#include "rsakeygen.h"
#include "rsaencrypt.h"
#include "rsadecrypt.h"
#include "RC4.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
int main(int argc,char* argv[])
{
	int numPlaintextBytes = 5; //amount of bytes in the plaintext
	int numNeededRSAKeyBits = 128; //desired amount of bits from RSA
	unsigned char * plainText = "Hello";
 	
	unsigned char * cypherText; //place to store cyphertext
	unsigned char * decodedText; //place to store decrypted text
	unsigned char * decryptedRC4fileKey; //place to store the RC4 key after it has been decrypted
	unsigned char RNGkey[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
	unsigned char RC4fileKey[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
	int RNGkeyLength = 8; //actual length of the RNG key
	int RC4fileKeyLength = 16; //actual length of RC4 file key
	
	cypherText = malloc(numPlaintextBytes +1);
	decodedText = malloc(numPlaintextBytes +1);
	decryptedRC4fileKey = malloc(RC4fileKeyLength);	

	mpz_t c; //for storing the encrypted RC4 key
	mpz_init(c);
 	rc4ctx_t rc4Context;

	//pad keys with zeros
	padZeroes(RNGkey,RNGkeyLength);
	padZeroes(RC4fileKey,RC4fileKeyLength);
	
	for (int i = 0; i < 16; i ++)
	{
		printf("RNGkey[%d] = %02x\n",i,RNGkey[i]);
	}
	for (int i = 0; i < 16; i ++)
	{
		printf("RC4fileKey[%d] = %02x\n",i,RC4fileKey[i]);
	}

// ************************************************************RSA keygen***********************************************************
	
	//generate RSA public (e) and private (d) keys
	generateKeyRSA(RNGkey,RNGkeyLength,numNeededRSAKeyBits);

// ************************************************************RC4 encryption*******************************************************

	//perform RC4 encryption
	RC4Encrypt(plainText,cypherText,numPlaintextBytes,RC4fileKey,RC4fileKeyLength);

// ************************************************************RSA encryption*******************************************************

	//encrypt RC4fileKey and store the cyphertext in variable c
	rsaEncrypt(RC4fileKey, c, rsaContext.e, rsaContext.n);

// ************************************************************RSA decryption*******************************************************

	//decrypt key and store the plaintext in variable decryptedRC4fileKey
	rsaDecrypt(decryptedRC4fileKey, c, rsaContext.d, rsaContext.n);

// ************************************************************RC4 decryption*******************************************************
	//decrypt cypherText and store the plaintext in variable decodedText
	RC4Decrypt(decodedText,cypherText,numPlaintextBytes,decryptedRC4fileKey,RC4fileKeyLength);

// *******************************************************************END***********************************************************
	mpz_clear(c);
	rsa_clear(&rsaContext);
}
