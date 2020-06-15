#include "rsakeygen.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h> 

typedef struct
{
	unsigned char S[256];
	int i;
	int j;
} rc4ctx_t;

rc4ctx_t rc4RNGContext;

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

void printError(char *message) {
    fprintf(stderr, "%s See Usage.\n", message);
    exit(0);
}

/**
 * @brief      The main function which interprets the terminal command, keys-files and operations are defined here
 *  
 *
 * @param[in]  argc  The count of arguments
 * @param      argv  The arguments array
 *
 * @return     returns 0 when complete
 */
int main(int argc, char* argv[]) {

	
	

	char *fpriv = NULL, *fpub = NULL; // file pointers
	unsigned char *key = NULL;
	int bitLen = 0, keyLen = 0;

	char *nonInts = NULL;


	FILE *priv = NULL, *pub = NULL;
	
	char c = 0;
	while (1) {
        static struct option long_options[] = 
        {
			{"bitLen", required_argument, 0, 'a'},
			{"fopub", required_argument, 0, 'b'},
            {"fopriv", required_argument, 0, 'c'},
            {"init", required_argument, 0, 'd'},
            {0,0,0,0} // shows end of list
        };

		
        int option_index = 0;
        opterr = 0;
        c = getopt_long_only (argc, argv, "a:b:c:d:", long_options, option_index);

		/* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) // stores values sent in through command line to be used by encryption and decryption algos
        {
			case 'a':
                bitLen = strtol(optarg, nonInts, 10); // bitLen is an integer
                break;

            case 'b':
                fpub = optarg;
                break;
            
            case 'c':
                fpriv = optarg;
                break;

			case 'd':
                key = optarg;
                break;

			default: // reaches here if invalid parameter or no argument
                printError("Invalid command!");
                break;
		}
	}

	if (fpriv == NULL || fpub == NULL || bitLen <= 0 || key == NULL) {
		printError("Invalid command!");
	}


	for (keyLen = 0; keyLen< 17; keyLen++) {
		if (key[keyLen] == 0)
			break;
	}

	if (keyLen == 0 || keyLen > 16) {
		printError("Please Enter Valid Key!");
	}

	if (nonInts!= NULL)
		printError("Please Enter Valid bitLen!");
		

	padZeroes(key, keyLen);

	   

	 
	// don't waste time processing the file if output file can't be created
    priv = fopen(fpriv, "w+");
    if (fpriv == NULL) {
        fprintf(stderr, "Could not open or create file: %s\n", fpriv);
        return 0;
    }

	pub = fopen(fpub, "w+");
    if (fpub == NULL) {
        fprintf(stderr, "Could not open or create file: %s\n", fpub);
        return 0;
	}

	generateKeyRSA(key, keyLen, bitLen);

	char * n = mpz_get_str(NULL,10, rsaContext.n);
	char * cd = mpz_get_str(NULL,10, rsaContext.d);
	char * ce = mpz_get_str(NULL,10, rsaContext.e);

	fprintf(pub, "%s\n", n);
	fprintf(priv, "%s\n", n);

	fprintf(pub, "%s\n", ce);
	fprintf(priv, "%s\n", cd);
	
	if (pub != NULL)
		fclose(pub);
	if (priv != NULL)	
		fclose(priv);	


	// code adapted from Zeta's answer at:
	//https://stackoverflow.com/questions/15691477/c-mpir-mpz-t-to-stdstring
	// In order to free the memory we need to get the right free function:
	void (*freefunc)(void *, size_t);
	mp_get_memory_functions (NULL, NULL, &freefunc);

	// In order to use free one needs to give both the pointer and the block
	// size. For tmp this is strlen(tmp) + 1, see [1].
	freefunc(cd, strlen(cd) + 1);
	freefunc(ce, strlen(ce) + 1);

	rsa_clear(&rsaContext);

	return 0;

}