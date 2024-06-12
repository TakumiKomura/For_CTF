#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "cryptography_lib.h"

// (Z/pZ)の最小の生成元を求める
unsigned long long generator(unsigned long long p) {
    // p-1の1,p-1以外の約数を求める
    unsigned long long divisor[10000];
    int index = 0;
    for (unsigned long long i = 2; i <= (p - 1) / 2; i++) {
        if ((p - 1) % i == 0) {
            divisor[index] = i;
            index++;
        }
    }
    unsigned long long g = 2;
    index = 0;
    // 求めた約数に対してg^(約数) mod p = 1であればgは生成元ではない
    while (divisor[index] != 0) {
        if (exp_operation(g, divisor[index], p) == 1) {
            g++;
            index = 0;
        }
        index++;
    }

    return g;
}

// Diffie_Hellman鍵配送方式を用いて、共通鍵を生成
unsigned long long Diffie_Hellman(unsigned long long a, unsigned long long b, unsigned long long g, unsigned long long p) {
    unsigned long long A, B;
    unsigned long long key_A, key_B;

    // Bob側 B=g^b mod p の計算
    B = exp_operation(g, b, p);

    // Alice側 A=g^a mod p の計算
    A = exp_operation(g, a, p);

    // Bob側 A^b=g^ab mod p の計算
    key_A = exp_operation(A, b, p);

    // Alice側 B^a=g^ab mod p の計算
    key_B = exp_operation(B, a, p);

    // Bob側の鍵とAlice側の鍵が違う場合
    if (key_A != key_B) {
        printf("error : faled generating Key\n");
        exit(EXIT_FAILURE);
    }

    // Alice,Bobどちらかの鍵を返す (AliceとBobは同じ鍵を持っている筈なので、どちらでもよい)
    return key_A;
}

// 高速指数演算法  g^exp mod pを高速に計算する関数
unsigned long long exp_operation(unsigned long long g, unsigned long long exp, unsigned long long p) {
    unsigned long long result = 1; // 計算結果

    while (exp > 0) {
        if (exp % 2 == 1) {
            result = result * g % p;
        }
        g = g * g % p;
        exp /= 2;
    }
    return result;
}

// ElGamal暗号の暗号化
unsigned long long ElGamal_enc(unsigned long long p, unsigned long long K, unsigned long long M) {
    return K * M % p;
}

// ElGamal暗号の復号化
unsigned long long ElGamal_dec(unsigned long long p, unsigned long long K, unsigned long long C) {
    unsigned long long K1;

    // Kの逆元K^(-1)を求める. K=g(α^b)
    // K*K^(-1) mod p =1 となる K^(-1)を求める

    K1 = extended_Euclid(K, p);
    return ((C * K1) % p);
}

// 拡張Euclid互除法
unsigned long long extended_Euclid(unsigned long long a, unsigned long long n) {
    unsigned long long u1, u2;        // 拡張部分
    unsigned long long r1, r2;        // Euclid 互除法
    unsigned long long q, w;        // q は商（r2/r1の床関数）の保持。w は r_k, u_k の計算用一時変数

    r1 = n;
    r2 = a;
    u1 = 0;
    u2 = 1;

    while (r1 > 0) {
        q = r2 / r1;
        w = r2 - q * r1;
        r2 = r1;
        r1 = w;
        w = u2 - q * u1;
        u2 = u1;
        u1 = w;
    }
    return ((u2 + n) % n);        // u2 が負数のこともあるので n を足して mod n しておく
}

// ElGamal暗号
// int ElGamal(void) {
//     unsigned long long a;     // Alice側の秘密鍵
//     unsigned long long b;     // Bob側の秘密鍵
//     unsigned long long p, g;   // 公開する情報
//     unsigned long long M, C;   // 平文及び暗号文
//     unsigned long long K;     // 共通鍵
//     unsigned long long C1;    // 復号後の値

//     // 各値の設定
//     a = 9;   // Aliceの秘密鍵 0<a<p
//     b = 3;   // Bobの秘密鍵 0<b<p
//     p = 57;   // p<32768の大きな素数
//     M = 11;   // 平文(メッセージ)

//     // (Z/pZ)の生成元gを見つける
//     g = generator(p);

//     // Diffie_Hellman鍵配送方式を用いて共通鍵(K)を生成
//     K = Diffie_Hellman(a, b, g, p);

//     // ElGamal暗号と鍵Kを使って、平文Mを暗号文Cに暗号化する
//     C = ElGamal_enc(p, K, M);

//     // 暗号文Cと鍵Kを用いて、復号を行う
//     C1 = ElGamal_dec(p, K, C);

//     // 結果の表示
//     printf("a:%ld, b:%ld, p:%ld, g:%ld\n", a, b, p, g);
//     printf("平文  :%ld\n", M);
//     printf("共通鍵:%ld\n", K);
//     printf("暗号文:%ld\n", C);
//     printf("復号  :%ld\n", C1);

//     return 0;
// }

// Euler関数
unsigned long long Euler(unsigned long long p, unsigned long long q) {
    if (p == q) {
        return (p * (p - 1));
    }
    return (p - 1) * (q - 1);
}

// 最大公約数 Greatest Common Divisor
unsigned long long gcd(unsigned long long a, unsigned long long b) {
    unsigned long long r;
    do {
        r = a % b;
        a = b;
        b = r;
    } while (r > 0);
    return a;
}

// 公開鍵生成 for RSA
unsigned long long public_key(unsigned long long Euler_n) {
    unsigned long long e;

    srand(1);
    do {
        e = rand() % Euler_n;
    } while (gcd(e, Euler_n) != 1);
    return e;
}

// 秘密鍵生成 for RSA
unsigned long long secret_key(unsigned long long Euler_n, unsigned long long e) {
    unsigned long long d = extended_Euclid(e, Euler_n); // eの逆元e^(-1) mod φ(n)を求める
    return d;
}

// RSA暗号化
unsigned long long RSA_enc(unsigned long long M, unsigned long long e, unsigned long long n) {
    long C;
    C = exp_operation(M, e, n);
    return C;
}

// RSAで復号化
unsigned long long RSA_dec(unsigned long long C, unsigned long long d, unsigned long long n) {
    unsigned long long C1;
    C1 = exp_operation(C, d, n);
    return C1;
}

// CRTで復号化
unsigned long long CRT_dec(unsigned long long C, unsigned long long d, unsigned long long p, unsigned long long q) {
    unsigned long long C2;
    unsigned long long n = p * q;
    unsigned long long x1 = exp_operation(C, d, p);
    unsigned long long x2 = exp_operation(C, d, q);
    unsigned long long p_ = extended_Euclid(p, q);
    unsigned long long q_ = extended_Euclid(q, p);
    C2 = (((x1 * ((q * q_) % n)) % n) + ((x2 * ((p * p_) % n)) % n)) % n;
    return C2;
}

// RSA署名
unsigned long long RSA_sign(unsigned long long M, unsigned long long d, unsigned long long n) {
    unsigned long long s;
    s = exp_operation(M, d, n);
    return s;
}

// RSA検証
unsigned long long RSA_ver(unsigned long long s, unsigned long long e, unsigned long long n) {
    unsigned long long v;
    v = exp_operation(s, e, n);
    return v;
}

// RSA暗号
// int RSA(void) {
//     unsigned long long p, q;    // 大きな素数
//     unsigned long long M;       // 平文
//     unsigned long long C1;      // RSA復号後の値
//     unsigned long long C2;      // CRT復号後の値
//     unsigned long long C;       // 暗号後の値
//     unsigned long long n;       // p*q
//     unsigned long long Euler_n; // Φ(n)
//     unsigned long long e;       // 公開鍵
//     unsigned long long d;       // eの逆元
//     unsigned long long s;       // 署名文
//     unsigned long long v;       // 検証後の値

//     M = 4028;
//     p = 97;
//     q = 101;
//     n = p * q;
//     Euler_n = Euler(p, q);
//     e = public_key(Euler_n);
//     d = secret_key(Euler_n, e);

//     C = RSA_enc(M, e, n);
//     C1 = RSA_dec(C, d, n);
//     C2 = CRT_dec(C, d, p, q);
//     s = RSA_sign(M, d, n);
//     v = RSA_ver(s, e, n);

//     printf("平文M       :\t %llu\n", M);
//     printf("素数p       :\t %llu\n", p);
//     printf("素数q       :\t %llu\n", q);
//     printf("公開鍵n     :\t %llu\n", n);
//     printf("Euler_n     :\t %llu\n", Euler_n);    
//     printf("公開鍵e     :\t %llu\n", e);
//     printf("秘密鍵d     :\t %llu\n", d);
//     printf("暗号化C     :\t %llu\n", C);
//     printf("RSA復号化C1 :\t %llu\n", C1);
//     printf("CRT復号化C2 :\t %llu\n", C2);
//     printf("署名文s     :\t %llu\n", s);
//     printf("検証v       :\t %llu\n", v);

//     return 0;
// }
