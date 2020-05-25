#include <gmp.h>
/**
 * @brief converts an mpz_t value to a string
 * 
 * @param o
 * @param decryptedfileKey
 * @return void
 */
void mpzToStr(mpz_t o, unsigned char * decryptedfileKey);
/**
 * @brief performs rsa decryption
 * 
 * @param decryptedRC4fileKey
 * @param c
 * @param d
 * @param n
 * @return void
 */
void rsaDecrypt(unsigned char * decryptedRC4fileKey, mpz_t c, mpz_t d, mpz_t n);
