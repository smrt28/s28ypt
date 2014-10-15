#include <stdint.h>
#include <string.h>
#include <iostream>
#include "s28box.h"


#define MIX1\
    do {\
    block64[0] ^= box1[b8[8]];\
    block64[1] ^= box2[b8[0]];\
    block64[0] ^= box3[b8[9]];\
    block64[1] ^= box1[b8[1]];\
    block64[0] ^= box2[b8[10]];\
    block64[1] ^= box3[b8[2]];\
    block64[0] ^= box1[b8[11]];\
    block64[1] ^= box2[b8[3]];\
    block64[0] ^= box3[b8[12]];\
    block64[1] ^= box1[b8[4]];\
    block64[0] ^= box2[b8[13]];\
    block64[1] ^= box3[b8[5]];\
    block64[0] ^= box1[b8[14]];\
    block64[1] ^= box2[b8[6]];\
    block64[0] ^= box3[b8[15]];\
    block64[1] ^= box1[b8[7]];\
    } while(0)

#define MIX2\
    do {\
    block64[0] ^= box4[b8[8]];\
    block64[1] ^= box3[b8[0]];\
    block64[0] ^= box2[b8[9]];\
    block64[1] ^= box4[b8[1]];\
    block64[0] ^= box3[b8[10]];\
    block64[1] ^= box2[b8[2]];\
    block64[0] ^= box4[b8[11]];\
    block64[1] ^= box3[b8[3]];\
    block64[0] ^= box2[b8[12]];\
    block64[1] ^= box4[b8[4]];\
    block64[0] ^= box3[b8[13]];\
    block64[1] ^= box2[b8[5]];\
    block64[0] ^= box4[b8[14]];\
    block64[1] ^= box3[b8[6]];\
    block64[0] ^= box2[b8[15]];\
    block64[1] ^= box4[b8[7]];\
    } while(0)

#define MIX3\
    do {\
    block64[0] ^= box3[b8[8]];\
    block64[1] ^= box2[b8[0]];\
    block64[0] ^= box1[b8[9]];\
    block64[1] ^= box3[b8[1]];\
    block64[0] ^= box2[b8[10]];\
    block64[1] ^= box1[b8[2]];\
    block64[0] ^= box3[b8[11]];\
    block64[1] ^= box2[b8[3]];\
    block64[0] ^= box1[b8[12]];\
    block64[1] ^= box3[b8[4]];\
    block64[0] ^= box2[b8[13]];\
    block64[1] ^= box1[b8[5]];\
    block64[0] ^= box3[b8[14]];\
    block64[1] ^= box2[b8[6]];\
    block64[0] ^= box1[b8[15]];\
    block64[1] ^= box3[b8[7]];\
    } while(0)



#define AMIX\
    do {\
        b32[0] ^= abox1[b8[4]];\
        b32[1] ^= abox2[b8[0]];\
        b32[0] ^= abox1[b8[5]];\
        b32[1] ^= abox2[b8[1]];\
        b32[0] ^= abox1[b8[6]];\
        b32[1] ^= abox2[b8[2]];\
        b32[0] ^= abox1[b8[7]];\
        b32[1] ^= abox2[b8[3]];\
    } while(0)

#define M1 0xb329a02147f6dd81
#define M2 0xa6bb183c0e172b13


template <typename INT> 
INT rol(INT val) {
        return (val << 1) | (val >> (sizeof(INT)*8-1));
}



// pass - uint64_t[4] - 256bits - the password
// k - uint64_t[24] - derived key
void derive_key(uint64_t *pass, uint64_t *k) {
    uint8_t * b8;
    uint32_t *b32;
    uint64_t tmp;
    b8 = (uint8_t *)&tmp;
    b32 = (uint32_t *)&tmp;

    k[0] = pass[0];
    k[1] = pass[1];
    k[2] = pass[2];
    k[3] = pass[3];

    for (size_t i = 4; i < 23; i++) {
        if (tmp > 18) {
            tmp = (k[i-1] & ~k[i-4]) | ((k[i-3] ^ M1) & (k[i - 2] ^ M2));
        } else {
            tmp = (k[i-1] | ~k[i-2]) & ((k[i-3] ^ M1) | (k[i - 4] ^ M2));
        }

        tmp = rol(tmp);
        AMIX;
        k[i] = tmp;                
    }
}


// block - 128 bit block
// k - derived key
void encrypt(void *block_, uint64_t *k) {
    uint8_t *b8 = (uint8_t *)block_;
    uint64_t * block64 = (uint64_t *)block_;

    block64[0] ^= k[22]; block64[1] ^= k[23];
    MIX1; block64[0] ^= k[0]; block64[1] ^= k[1];
    MIX2; block64[0] ^= k[2]; block64[1] ^= k[3];
    MIX3; block64[0] ^= k[4]; block64[1] ^= k[5];
    MIX1; block64[0] ^= k[6]; block64[1] ^= k[7];
    MIX2; block64[0] ^= k[8]; block64[1] ^= k[9];
    MIX3; block64[0] ^= k[10]; block64[1] ^= k[11];
    MIX1; block64[0] ^= k[12]; block64[1] ^= k[13];
    MIX2; block64[0] ^= k[14]; block64[1] ^= k[15];
    MIX3; block64[0] ^= k[16]; block64[1] ^= k[17];
    MIX1; block64[0] ^= k[18]; block64[1] ^= k[19];
    MIX2; block64[0] ^= k[20]; block64[1] ^= k[21];
    MIX3; block64[0] ^= k[22]; block64[1] ^= k[23];
}


int main() {

    return 0;
}

