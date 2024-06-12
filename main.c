#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "cryptography_lib.h"

// ElGamal暗号
int ElGamal(void) {
    unsigned long long a;     // Alice側の秘密鍵
    unsigned long long b;     // Bob側の秘密鍵
    unsigned long long p, g;   // 公開する情報
    unsigned long long M, C;   // 平文及び暗号文
    unsigned long long K;     // 共通鍵
    unsigned long long C1;    // 復号後の値

    // 各値の設定
    a = 9;   // Aliceの秘密鍵 0<a<p
    b = 3;   // Bobの秘密鍵 0<b<p
    p = 57;   // p<32768の大きな素数
    M = 11;   // 平文(メッセージ)

    // (Z/pZ)の生成元gを見つける
    g = generator(p);

    // Diffie_Hellman鍵配送方式を用いて共通鍵(K)を生成
    K = Diffie_Hellman(a, b, g, p);

    // ElGamal暗号と鍵Kを使って、平文Mを暗号文Cに暗号化する
    C = ElGamal_enc(p, K, M);

    // 暗号文Cと鍵Kを用いて、復号を行う
    C1 = ElGamal_dec(p, K, C);

    // 結果の表示
    printf("a:%ld, b:%ld, p:%ld, g:%ld\n", a, b, p, g);
    printf("平文  :%ld\n", M);
    printf("共通鍵:%ld\n", K);
    printf("暗号文:%ld\n", C);
    printf("復号  :%ld\n", C1);

    return 0;
}

// RSA暗号
int RSA(void) {
    unsigned long long p, q;    // 大きな素数
    unsigned long long M;       // 平文
    unsigned long long C1;      // RSA復号後の値
    unsigned long long C2;      // CRT復号後の値
    unsigned long long C;       // 暗号後の値
    unsigned long long n;       // p*q
    unsigned long long Euler_n; // Φ(n)
    unsigned long long e;       // 公開鍵
    unsigned long long d;       // eの逆元
    unsigned long long s;       // 署名文
    unsigned long long v;       // 検証後の値

    M = 4028;
    p = 97;
    q = 101;
    n = p * q;
    Euler_n = Euler(p, q);
    e = public_key(Euler_n);
    d = secret_key(Euler_n, e);

    C = RSA_enc(M, e, n);
    C1 = RSA_dec(C, d, n);
    C2 = CRT_dec(C, d, p, q);
    s = RSA_sign(M, d, n);
    v = RSA_ver(s, e, n);

    printf("平文M       :\t %llu\n", M);
    printf("素数p       :\t %llu\n", p);
    printf("素数q       :\t %llu\n", q);
    printf("公開鍵n     :\t %llu\n", n);
    printf("Euler_n     :\t %llu\n", Euler_n);    
    printf("公開鍵e     :\t %llu\n", e);
    printf("秘密鍵d     :\t %llu\n", d);
    printf("暗号化C     :\t %llu\n", C);
    printf("RSA復号化C1 :\t %llu\n", C1);
    printf("CRT復号化C2 :\t %llu\n", C2);
    printf("署名文s     :\t %llu\n", s);
    printf("検証v       :\t %llu\n", v);

    return 0;
}

int main(void){
	// printf("ElGamal\n");
	// ElGamal();
	// printf("\n");
	// printf("RSA\n");
	// RSA();
    printf("%llu\n", extended_Euclid(7, 4));
	return 0;
}
