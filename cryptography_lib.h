#ifndef CRYPTOGRAPHY_LIB_H
#define CRYPTOGRAPHY_LIB_H

unsigned long long exp_operation(unsigned long long g,unsigned long long exp,unsigned long long p);
unsigned long long Diffie_Hellman(unsigned long long a,unsigned long long b,unsigned long long g,unsigned long long p);
unsigned long long ElGamal_enc(unsigned long long p,unsigned long long K,unsigned long long M);
unsigned long long ElGamal_dec(unsigned long long p,unsigned long long K,unsigned long long C);
unsigned long long extended_Euclid(unsigned long long a,unsigned long long n);
unsigned long long generator(unsigned long long p);
unsigned long long Euler(unsigned long long p, unsigned long long q);
unsigned long long gcd(unsigned long long a, unsigned long long b);
unsigned long long public_key(unsigned long long Euler_n);
unsigned long long secret_key(unsigned long long Euler_n, unsigned long long e);
unsigned long long RSA_enc(unsigned long long M, unsigned long long e, unsigned long long n);
unsigned long long RSA_dec(unsigned long long C, unsigned long long d, unsigned long long n);
unsigned long long CRT_dec(unsigned long long C, unsigned long long d, unsigned long long p, unsigned long long q);
unsigned long long RSA_sign(unsigned long long M, unsigned long long d, unsigned long long n);
unsigned long long RSA_ver(unsigned long long s, unsigned long long e, unsigned long long n);

#endif // CRYPTOGRAPHY_LIB_H
