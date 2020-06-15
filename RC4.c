
#include "RC4.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

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
