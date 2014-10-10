#include <string.h>
#include <iostream>
#include "s28box.h"



#define K1(a, b, c, d, e, f, g, h) (\
    ((box1[~a] ^ box2[b]) | (box3[c] ^ box4[d])) &\
    ((box1[e] ^ box2[f]) | (box3[g] ^ box4[h])))

#define K2(a, b, c, d, e, f, g, h) (\
    ((box1[a] ^ box3[b]) & (box2[c] ^ box4[d])) |\
    ((box1[e] ^ box3[f]) & (box2[g] ^ box4[~h])))

#define K3(a, b, c, d, e, f, g, h) (\
    ((box1[uint8_t(a + 107)] ^ box2[b]) | (box3[c] ^ box4[d])) &\
    ((box1[e] ^ box2[f]) | (box3[uint8_t(g - 107)] ^ box4[h])))

#define K4(a, b, c, d, e, f, g, h) (\
    (box1[a] ^ ~(box2[b] & box3[c]) ^ box4[d]) ^\
    (box1[e] ^ ~(box2[f] & box3[g]) ^ box4[h]))

#define K5(a, b, c, d, e, f, g, h) (\
    (~(box1[uint8_t(a + c)] ^ box2[b]) & box3[c] ^ box4[uint8_t(d + b)]) ^\
    (box1[uint8_t(e + g)] ^ box2[f] & ~(box3[g] ^ box4[uint8_t(h + f)])))

#define K6(a, b, c, d, e, f, g, h) (\
    ((box2[a] ^ box3[b]) | (box4[c] ^ box1[d])) &\
    ((box3[e] ^ box4[f]) | (box1[g] ^ box2[h])))



int main() {

    uint8_t block[16];
    memset(block, 0, sizeof(block));

    uint64_t * block64 = (uint64_t *)block;
    uint8_t * b8 = block;

    uint64_t key[23];
    memset(key, 0, sizeof(key));
    

    block64[0] ^= key[0];
    block64[1] ^= K1(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[1];
    block64[0] ^= K2(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[2];
    
    block64[1] ^= K3(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[3];
    block64[0] ^= K4(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[4];

    block64[1] ^= K5(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[5];
    block64[0] ^= K6(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[6];
    
    block64[1] ^= K5(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[7];
    block64[0] ^= K4(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[8];

    block64[1] ^= K3(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[9];
    block64[0] ^= K2(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[10];
    
    block64[1] ^= K1(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[11];
    block64[0] ^= K2(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[12];

    block64[1] ^= K3(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[13];
    block64[0] ^= K4(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[14];

    block64[1] ^= K5(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[15];
    block64[0] ^= K6(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[16];

    block64[1] ^= K5(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[17];
    block64[0] ^= K4(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[18];

    block64[1] ^= K3(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[19];
    block64[0] ^= K2(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[20];

    block64[1] ^= K1(b8[0],b8[1],b8[2],b8[3],b8[4],b8[5],b8[6],b8[7]) ^ key[21];
    block64[0] ^= K2(b8[8],b8[9],b8[10],b8[11],b8[12],b8[13],b8[14],b8[15]) ^ key[22];



    
    std::cout << block64[0] << " " << block64[1] << std::endl;






    return 0;
}

