#include <gmp.h>
/**
 * @brief converts a string to an mpz_t value
 * 
 * @param m
 * @param RC4fileKey
 * @return void
 */
void strToMpz(mpz_t m, unsigned char * RC4fileKey);
/**
 * @brief performs rsa encryption
 * 
 * @param RC4fileKey
 * @param c
 * @param e
 * @param n
 * @return void
 */
void rsaEncrypt(unsigned char * RC4fileKey, mpz_t c, mpz_t e, mpz_t n);
