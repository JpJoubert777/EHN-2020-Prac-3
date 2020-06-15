#include "rsaencrypt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

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

void printError(char *message) {
    fprintf(stderr, "%s See Usage.\n", message);
    exit(0);
}


int main(int argc, char* argv[]) {

	char *fo = NULL, *fpub = NULL; // file pointers
	unsigned char *key = NULL;
	int keyLen = 0;



	FILE *wFile = NULL, *pub = NULL;
	
	char c = 0;
	while (1) {
        static struct option long_options[] = 
        {
			{"key", required_argument, 0, 'a'},
			{"fo", required_argument, 0, 'b'},
            {"fopub", required_argument, 0, 'c'},
            {0,0,0,0} // shows end of list
        };

		
        int option_index = 0;
        opterr = 0;
        c = getopt_long_only (argc, argv, "a:b:c:", long_options, option_index);

		/* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) // stores values sent in through command line to be used by encryption and decryption algos
        {
			case 'a':
                key = optarg;
                break;

            case 'b':
                fo = optarg;
                break;
            
            case 'c':
                fpub = optarg;
                break;

			default: // reaches here if invalid parameter or no argument
                printError("Invalid command!");
                break;
		}
	}

	if (fo == NULL || fpub == NULL || key == NULL) {
		printError("Invalid command!");
	}


	for (keyLen = 0; keyLen< 17; keyLen++) {
		if (key[keyLen] == 0)
			break;
	}

	if (keyLen == 0 || keyLen > 16) {
		printError("Please Enter Valid Key!");
	}

	padZeroes(key, keyLen);

	   

	 
	pub = fopen(fpub, "r");
    if (pub == NULL) {
        fprintf(stderr, "Could not open %s or File not found\n", fpub);
        return 0;
    }

	wFile = fopen(fo, "w+");
    if (wFile == NULL) {
        fprintf(stderr, "Could not open or create file: %s\n", fo);
        return 0;
    }

	mpz_t out; //for storing the encrypted RC4 key
	mpz_init(out);
 	
	mpz_t n;
	mpz_t e;

	mpz_init(n);
	mpz_init(e);

	char *line = NULL;
    size_t len = 0;
	ssize_t read;

	if ((read = getline(&line, &len, fpub)) != -1) {
        if (mpz_set_str(n,line, 10) != 0) {
			printError("Invalid n value!");
		}
    }

	if ((read = getline(&line, &len, fpub)) != -1) {
        if (mpz_set_str(e,line, 10) != 0) {
			printError("Invalid e value!");
		}
    }

	rsaEncrypt(key, out, e, n);

	char * cc = mpz_get_str(NULL,10, out);

	fprintf(wFile, "%s\n", cc);

	
	if (wFile != NULL)
		fclose(wFile);
	if (pub != NULL)	
		fclose(pub);	


	// code adapted from Zeta's answer at:
	//https://stackoverflow.com/questions/15691477/c-mpir-mpz-t-to-stdstring
	// In order to free the memory we need to get the right free function:
	void (*freefunc)(void *, size_t);
	mp_get_memory_functions (NULL, NULL, &freefunc);

	// In order to use free one needs to give both the pointer and the block
	// size. For tmp this is strlen(tmp) + 1, see [1].
	freefunc(cc, strlen(cc) + 1);

	mpz_clear(out);
	mpz_clear(n);
	mpz_clear(e);
	

	return 0;

}
