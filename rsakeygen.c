#include "rsakeygen.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "RC4.h"

rc4ctx_t rc4RNGContext; 


void rsa_init(rsactx_t * rsactx)
{
	mpz_init(rsactx->p);
	mpz_init(rsactx->q);
	mpz_init(rsactx->n);
	mpz_init(rsactx->sigma);
	mpz_init(rsactx->e);
	mpz_init(rsactx->d); 
}

void rsa_clear(rsactx_t * rsactx)
{
	mpz_clear(rsactx->p);
	mpz_clear(rsactx->q);
	mpz_clear(rsactx->n);
	mpz_clear(rsactx->sigma);
	mpz_clear(rsactx->e);
	mpz_clear(rsactx->d); 
}

void padZeroes(unsigned char * key, int keylen)
{

	if (keylen < 16)
	{
		for (int i = keylen; i < 16; i ++)
		{
			key[i] = 0;
		}
			
	}

}
void rseed(unsigned char * key, int keylen)
{
	rc4_init(&rc4RNGContext, key, keylen);
}

unsigned char rrand()
{
	return rc4_getByte(&rc4RNGContext);
}

void getprime(mpz_t p,int bits)
{
	//initialize p with the required number of bits
	mpz_init2(p,bits/2 -1);
	//set MSB
	mpz_setbit(p,bits/2 -1);
	//iterate from MSBs to LSBs
	for (int i = (bits/2 -1)-1; i > -1; i--)
	{
		//generate RC4 random number, if its LSB is 1 then set the corresponding bit in p, otherwise clear it
		if ((rrand() & 1) == 1)
			mpz_setbit(p,i);
		else
			mpz_clrbit(p,i);
	}
	//get the next prime bigger than p
	mpz_nextprime(p,p);

}

void generateKeyRSA(unsigned char * RNGkey,int RNGkeyLength,int numNeededRSAKeyBits)
{	
	//init RSA context for key encryption/decryption	
	rsa_init(&rsaContext);
	//seed the RC4 RNG 
 	rseed(RNGkey,RNGkeyLength);
	printf("\n\nRSA key generation:\n");
	//get prime for p and q
	getprime(rsaContext.p,numNeededRSAKeyBits);
	getprime(rsaContext.q,numNeededRSAKeyBits);

	gmp_printf("p = %Zd\n",rsaContext.p);
	if (mpz_probab_prime_p(rsaContext.p,50) == 0)
		printf("Error, p is not prime!\n");

	gmp_printf("q = %Zd\n",rsaContext.q);
	if (mpz_probab_prime_p(rsaContext.q,50) == 0)
		printf("Error, q is not prime!\n");

	// find n = p * q
	mpz_mul(rsaContext.n,rsaContext.p,rsaContext.q);
	gmp_printf("n = %Zd\n",rsaContext.n);
	// variables for computing p-1 and q-1
	mpz_t p_1;
	mpz_t q_1;
	mpz_t decimal_1;
	// init
	mpz_init(p_1);
	mpz_init(q_1);
	mpz_init(decimal_1);
	mpz_set_ui(decimal_1,1);
	// compute p-1 and q-1
	mpz_sub(p_1,rsaContext.p,decimal_1);
	mpz_sub(q_1,rsaContext.q,decimal_1);
	// find sigma = (p-1) * (q-1)
	mpz_mul(rsaContext.sigma,p_1,q_1);
	gmp_printf("sigma = %Zd\n",rsaContext.sigma);
	//find an appropriate value for e
	if (65537 < mpz_get_ui(rsaContext.sigma))
		mpz_set_ui(rsaContext.e,65537);
	else
		if (17 < mpz_get_ui(rsaContext.sigma))
			mpz_set_ui(rsaContext.e,17);
	else
		if (3 < mpz_get_ui(rsaContext.sigma))
			mpz_set_ui(rsaContext.e,3);
	gmp_printf("e = %Zd\n",rsaContext.e);

	mpz_t gcd;
	mpz_init(gcd);
	mpz_gcd(gcd,rsaContext.e,rsaContext.sigma);
	if (mpz_get_ui(gcd) != 1)
		printf("Error, sigma not relative prime to e = %lu! gcd = %lu\n",mpz_get_ui(rsaContext.e),mpz_get_ui(gcd));

	// compute d
	mpz_invert(rsaContext.d,rsaContext.e,rsaContext.sigma);
	gmp_printf("d = %Zd\n",rsaContext.d);

	// clear variables that are no longer needed
	mpz_clear(p_1);
	mpz_clear(q_1);
	mpz_clear(decimal_1);
	mpz_clear(gcd);
}

