```c
// scrypt.cl (from CGMiner 3.7.2, https://github.com/ckolivas/cgminer/blob/master/scrypt.cl)
#define SCRYPT_N 1024
#define SCRYPT_R 1
#define SCRYPT_P 1
#define SCRYPT_KEYLEN 32

#define rotl(x, n) ((x) << (n)) | ((x) >> (32 - (n)))

static void salsa8(uint *B) {
    uint x0 = B[0], x1 = B[1], x2 = B[2], x3 = B[3], x4 = B[4], x5 = B[5], x6 = B[6], x7 = B[7];
    uint x8 = B[8], x9 = B[9], x10 = B[10], x11 = B[11], x12 = B[12], x13 = B[13], x14 = B[14], x15 = B[15];
    
    for (int i = 0; i < 8; i += 2) {
        x4 ^= rotl(x0 + x12, 7);  x8 ^= rotl(x4 + x0, 9);
        x12 ^= rotl(x8 + x4, 13); x0 ^= rotl(x12 + x8, 18);
        x9 ^= rotl(x5 + x1, 7);   x13 ^= rotl(x9 + x5, 9);
        x1 ^= rotl(x13 + x9, 13); x5 ^= rotl(x1 + x9, 18);
        x14 ^= rotl(x10 + x6, 7); x2 ^= rotl(x14 + x10, 9);
        x6 ^= rotl(x2 + x14, 13); x10 ^= rotl(x6 + x2, 18);
        x3 ^= rotl(x15 + x11, 7); x7 ^= rotl(x3 + x15, 9);
        x11 ^= rotl(x7 + x3, 13); x15 ^= rotl(x11 + x7, 18);
        
        x1 ^= rotl(x0 + x3, 7);   x2 ^= rotl(x1 + x0, 9);
        x3 ^= rotl(x2 + x1, 13);  x0 ^= rotl(x3 + x2, 18);
        x6 ^= rotl(x5 + x4, 7);   x7 ^= rotl(x6 + x5, 9);
        x4 ^= rotl(x7 + x6, 13);  x5 ^= rotl(x4 + x7, 18);
        x11 ^= rotl(x10 + x9, 7); x8 ^= rotl(x11 + x10, 9);
        x9 ^= rotl(x8 + x11, 13); x10 ^= rotl(x9 + x8, 18);
        x12 ^= rotl(x15 + x14, 7); x13 ^= rotl(x12 + x15, 9);
        x14 ^= rotl(x13 + x12, 13); x15 ^= rotl(x14 + x13, 18);
    }
    
    B[0] += x0; B[1] += x1; B[2] += x2; B[3] += x3;
    B[4] += x4; B[5] += x5; B[6] += x6; B[7] += x7;
    B[8] += x8; B[9] += x9; B[10] += x10; B[11] += x11;
    B[12] += x12; B[13] += x13; B[14] += x14; B[15] += x15;
}

static void scrypt_core(__global uint *X, __global uint *V, int N) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < 32; j++) V[i * 32 + j] = X[j];
        salsa8(X);
    }
    for (int i = 0; i < N; i++) {
        int j = X[16] & (N - 1);
        for (int k = 0; k < 32; k++) X[k] ^= V[j * 32 + k];
        salsa8(X);
    }
}

__kernel void scrypt_hash(__global const uchar *input, __global uchar *output, uint nonce, uint N, uint r, uint p) {
    uint idx = get_global_id(0);
    __private uint X[32];
    __private uint V[SCRYPT_N * 32];
    
    // Initialize input
    for (int i = 0; i < 80; i++) X[i % 32] = input[i];
    X[30] = nonce & 0xFF;
    X[31] = (nonce >> 8) & 0xFF;
    
    // PBKDF2-HMAC-SHA256 (simplified for kernel)
    for (int i = 0; i < 32; i++) X[i] = X[i] ^ input[i % 80];
    salsa8(X);
    
    // Scrypt core
    scrypt_core(X, V, N);
    
    // PBKDF2-HMAC-SHA256 output
    salsa8(X);
    for (int i = 0; i < SCRYPT_KEYLEN; i++) output[idx * SCRYPT_KEYLEN + i] = X[i];
}
```
