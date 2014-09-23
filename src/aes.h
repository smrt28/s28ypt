#ifndef S28_AES_H
#define S28_AES_H

#include <openssl/aes.h>
#include "safemem.h"
namespace s28 {

class AES_t {
    struct Secret_t {
        AES_KEY ekey;
        AES_KEY dkey;
    };

public:
    static const size_t BLOCK_SIZE = AES_BLOCK_SIZE;
    static const size_t KEY_SIZE = 32;

    void init(const char *key) {        
        AES_set_encrypt_key((unsigned char *)key, 256, &keys->ekey);
        AES_set_decrypt_key((unsigned char *)key, 256, &keys->dkey);
    }

    inline void encrypt(char *in, char *out) {
        AES_encrypt((unsigned char *)in, (unsigned char *)out, &keys->ekey);
    }

    inline void decrypt(char *in, char *out) {
        AES_decrypt((const unsigned char *)in, (unsigned char *)out, &keys->dkey);
    }

private:
    SafePtr_t<Secret_t> keys;
};



}


#endif
