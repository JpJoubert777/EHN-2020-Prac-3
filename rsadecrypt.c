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


void printUsage() {
	printf("USAGE\n");
}

void printError(char *message) {
    fprintf(stderr, "%s See Usage.\n", message);
    printUsage();
    exit(0);
}

void printHelp() {
	printf("HELP!!!\n");
	printUsage();
	exit(0);
}

int main(int argc, char* argv[]) {

	static int hflg = 0;
	static int edflg = 0;

	char *fi = NULL, *fo = NULL, *fkey = NULL;

	unsigned char key[16] = {0};

	unsigned char *fiBuffer = NULL, *foBuffer = NULL;

	FILE *keyFile = NULL, *rFile = NULL, *wFile = NULL;

	int bufSize = 1048576, numBytes = 0, keyLen = 0;
	
	char c = 0;
	while (1) {
        static struct option long_options[] = 
        {
            {"e", no_argument, &edflg, 2}, // stores all the possible arguments in a list
            {"d", no_argument, &edflg, 1},
            {"h", no_argument, &hflg, 1},
			{"fi", required_argument, 0, 'a'},
            {"fo", required_argument, 0, 'b'},
            {"key", required_argument, 0, 'c'},
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
			case 0:
                if (long_options[option_index].name != 0)
                    break;
			case 'a':
                fi = optarg;
                break;

            case 'b':
                fo = optarg;
                break;
            
            case 'c':
                fkey = optarg;
                break;

			default: // reaches here if invalid parameter or no argument
                printError("Invalid command!");
                break;
		}
	}

	// NOTE: all print utility functions will exit the program after showing the messages
    if (hflg == 1) 
        printHelp();

    if (edflg == 0) 
        printError("Please specify Encryption or Decrytion mode!");
	
	edflg--; // move edflg from 1 and 2 to 0 and 1
    // from here if encryption if 1 and decryption if 0 for edflg

	if (fi == NULL || fo == NULL) {
		printError("Invalid command!");
	}

	if (fkey == NULL) {
		printf("Enter the key: ");
		scanf("%s", key);
	}
	else {
		keyFile = fopen(fkey, "r");
		if (keyFile == NULL && key == NULL) {
			fprintf(stderr, "Could not open %s or File not found\n", fkey);
			return 0;
		}

		while (1) {
			c = fgetc(keyFile);
			if (c == EOF)
				break;
			else {
				if (keyLen >= 16) {
					printf("Key longer than 16 characters. Please input valid key");
					exit(0);
				}
				key[keyLen++] = c;		
			}
		}

	}

	 

	// Open and hold the files
	rFile = fopen(fi, "r");
    if (rFile == NULL) {
        fprintf(stderr, "Could not open %s or File not found\n", fi);
        return 0;
    }    

	 
	// don't waste time processing the file if output file can't be created
    wFile = fopen(fo, "w+");
    if (wFile == NULL) {
        fprintf(stderr, "Could not open or create file: %s\n", fo);
        return 0;
    }

	fiBuffer = (unsigned char *)calloc(bufSize, sizeof(char)); 	// Allocate 1MB space by default 
	
	while (1) {
		c = fgetc(rFile);
		if (c == EOF)
			break;
		else {
			if (numBytes >= bufSize) {
				bufSize += 1048576; //increase buffer size by 1MB when more space required.
				fiBuffer = (unsigned char *)realloc(fiBuffer, bufSize);
			}
			fiBuffer[numBytes++] = c;
		}
	}

	
	if (edflg) // encrypt
		RC4Encrypt(fiBuffer, foBuffer, numBytes, key, keyLen);
	else 
		RC4Decrypt(foBuffer, fiBuffer, numBytes, key, keyLen);

	fclose(keyFile);
	fclose(rFile);
	fclose(wFile);	

	return 0;

}