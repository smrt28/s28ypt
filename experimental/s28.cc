#include <string.h>
#include <iostream>
#include "s28box.h"

#define K1(a, b, c, d, e, f, g, h) (\
    ((box1[a] ^ box2[b]) | (box3[c] ^ box4[d])) & \
    ((box5[e] ^ box6[f]) | (box7[g] ^ box8[h]))   \
    )

#define K2(a, b, c, d, e, f, g, h) (\
    ((box2[a] & box3[b]) | (box4[c] & box5[d])) ^ \
    ((box6[e] & box7[f]) | (box8[g] & box1[h]))   \
    )


#define K3(a, b, c, d, e, f, g, h) (\
    ((box3[a] ^ box4[b]) & (box5[c] ^ box6[d])) | \
    ((box7[e] ^ box8[f]) & (box1[g] ^ box2[h]))   \
    )

#define K4(a, b, c, d, e, f, g, h) (\
    ((box4[a] | box5[b]) & (box6[c] | box7[~d])) ^ \
    ((box8[e] | box1[f]) & (box2[g] | box3[h]))   \
    )




#define MIX\
    do {\
    block64[0] ^= box1[b8[8]];\
    block64[1] ^= box1[b8[0]];\
    block64[0] ^= box2[b8[9]];\
    block64[1] ^= box2[b8[1]];\
    block64[0] ^= box3[b8[10]];\
    block64[1] ^= box3[b8[2]];\
    block64[0] ^= box4[b8[11]];\
    block64[1] ^= box4[b8[3]];\
    block64[0] ^= box1[b8[12]];\
    block64[1] ^= box1[b8[4]];\
    block64[0] ^= box2[b8[13]];\
    block64[1] ^= box2[b8[5]];\
    block64[0] ^= box3[b8[14]];\
    block64[1] ^= box3[b8[6]];\
    block64[0] ^= box4[b8[15]];\
    block64[1] ^= box4[b8[7]];\
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



template <typename INT> 
INT rol(INT val) {
        return (val << 1) | (val >> (sizeof(INT)*8-1));
}

int main() {

    uint8_t block[16];
    memset(block, 0, sizeof(block));

    uint8_t * b8;
    uint32_t *b32;


    uint64_t k[20];
    memset(k, 0, sizeof(k));
    
    uint64_t tmp;
    b8 = (uint8_t *)&tmp;
    b32 = (uint32_t *)&tmp;

    for (size_t i = 5; i < 23; i++) {

        if (tmp > 18) {
            tmp = (k[i-1] & k[i-4]) | (k[i-3] & k[i - 2]);
        } else {
            tmp = (k[i-1] | k[i-2]) & (k[i-3] | k[i - 4]);
        }

        tmp = rol(tmp);
        AMIX;
        k[i] = tmp;                
    }

    
    b8 = block;
    uint64_t * block64 = (uint64_t *)block;

    MIX; block64[0] ^= k[0]; block64[1] ^= k[1];
    MIX; block64[0] ^= k[2]; block64[1] ^= k[3];
    MIX; block64[0] ^= k[4]; block64[1] ^= k[5];
    MIX; block64[0] ^= k[6]; block64[1] ^= k[7];
    MIX; block64[0] ^= k[8]; block64[1] ^= k[9];
    MIX; block64[0] ^= k[10]; block64[1] ^= k[11];
    MIX; block64[0] ^= k[12]; block64[1] ^= k[13];
    MIX; block64[0] ^= k[14]; block64[1] ^= k[15];
    MIX; block64[0] ^= k[16]; block64[1] ^= k[17];
    MIX; block64[0] ^= k[18]; block64[1] ^= k[19];
    MIX; block64[0] ^= k[20]; block64[1] ^= k[21];
    MIX; block64[0] ^= k[22]; block64[1] ^= k[23];

    std::cout << std::hex << block64[0] << " " << block64[1] << std::endl;

    return 0;
}

