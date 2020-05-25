#include "rsadecrypt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

void mpzToStr(mpz_t o, unsigned char * decryptedRC4fileKey)
{
	//code for converting the mpz_t integer into a string
	// each byte is extracted with masking and right shifting
	// this is done as follows: byteval[i] = o AND 255*256^i 
	// followed by byteval[i] = byteval[i]/256^i
	mpz_t byteVal;
	mpz_init(byteVal);

	mpz_t AND255; 
	mpz_init(AND255);

	mpz_t div256;
	mpz_init(div256);
	//for each byte
	for (int i = 0; i < 16; i++)
	{
		//set the values
		mpz_set_ui(AND255,255); 
		mpz_set_ui(div256,256);
		mpz_pow_ui(div256,div256,i);
		mpz_mul(AND255,AND255,div256);
		//extract the byte
		mpz_and(byteVal,o,AND255);
		mpz_divexact(byteVal,byteVal,div256);
		decryptedRC4fileKey[15-i] = (int)(mpz_get_ui(byteVal));
	}
	for (int i = 0; i < 16; i++)
		printf("decryptedRC4fileKey[%d] = %02x\n",i,decryptedRC4fileKey[i]);
	mpz_clear(div256);
	mpz_clear(AND255);
	mpz_clear(byteVal);
}
void rsaDecrypt(unsigned char * decryptedRC4fileKey, mpz_t c, mpz_t d, mpz_t n)
{
	mpz_t o;
	mpz_init(o);
	printf("\n");
	printf("RSA decrypted key:\n");
	mpz_powm_sec(o,c,d,n);
	gmp_printf("o = %Zd\n",o);
	//convert the mpz_t integer into a string
	mpzToStr(o,decryptedRC4fileKey);
	mpz_clear(o);
}
