#include "rsaencrypt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

void strToMpz(mpz_t m, unsigned char * RC4fileKey)
{
	//convert first char to int
	int temp = RC4fileKey[0];
	
	//set m to that first int
	mpz_set_ui(m,temp);

	//for every next byte
	for (int i = 1; i < 16; i++)
	{ 
		//convert char to int
		temp = RC4fileKey[i];
		//shift left one byte
		mpz_mul_ui(m,m,256);	
		//concatenate the int
		mpz_add_ui(m,m,temp);
	}
	printf("\n");
	printf("RSA message (decimal):\n");
	gmp_printf("m = %Zd\n",m);
}

void rsaEncrypt(unsigned char * RC4fileKey, mpz_t c, mpz_t e, mpz_t n)
{
	mpz_t m;
	mpz_init(m);
	//convert the RC4fileKey string into an mpz_t integer
	strToMpz(m,RC4fileKey);

	printf("\n");
	printf("RSA encrypted key:\n");
	mpz_powm_sec(c,m,e,n);
	gmp_printf("c = %Zd\n",c);
	mpz_clear(m);
}
