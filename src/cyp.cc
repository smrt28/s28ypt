

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>
#include <unistd.h>

#include <stdlib.h>
#include <sys/mman.h>

#include <string>
#include <exception>
#include <iostream>
#include <openssl/rand.h>

#include "safemem.h"
#include "textutils.h"

template<typename T_t, size_t CNT = 1>
class SafePtr_t {
public:
    SafePtr_t() : t((T_t *)s28::safe_malloc(sizeof(T_t[CNT])))
    {}

    ~SafePtr_t() {
        s28::safe_free((void *)t);
    }

    void zero() {
        memset(t, 0, size);
    }

    T_t * get() { return t; }
    const T_t * get() const { return t; }

    static const size_t size = sizeof(T_t[CNT]);

    T_t * operator->() {
        return t;
    }

private:
    SafePtr_t & operator=(const SafePtr_t &);
    SafePtr_t(const SafePtr_t &);

    T_t *t;
};


class Password_t {
    typedef SafePtr_t<char, 128 + 1> PassMem_t;    
public:
    Password_t(const char *pass) {
        p.zero();
        strncpy(p.get(), pass, PassMem_t::size - 1);
    }
    
    size_t size() const {
        return strlen(p.get());
    }

    const char * c_str() const {
        return p.get();
    }

private:
    PassMem_t p;
};

class Seed_t {
    static const size_t SEED_SIZE = SHA256_DIGEST_LENGTH;
public:
    Seed_t() {
        RAND_bytes(seed.get(), SEED_SIZE);
    }
    SafePtr_t<unsigned char, SEED_SIZE> seed;    
};

class AES_t {
    struct Secret_t {
        AES_KEY ekey;
        AES_KEY dkey;
    };

    static const size_t KEY_SIZE = SHA256_DIGEST_LENGTH;

public:
    static const size_t BLOCK_SIZE = AES_BLOCK_SIZE;

    class Context_t {
    public:
        Context_t() {
            reset();
        }
        char block[BLOCK_SIZE];
        void reset() {
            memset(block, 0, sizeof(block));
        }
    };



    void init(const Password_t &pw) {
        SafePtr_t<unsigned char, KEY_SIZE> rawKey;
        SafePtr_t<SHA256_CTX> ctx;
        unsigned char *hash = rawKey.get();
        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), pw.c_str(), pw.size());
        SHA256_Final(hash, ctx.get()); 
       
        for (int i = 0; i < 300000; ++i) {
            SHA256_Init(ctx.get());
            SHA256_Update(ctx.get(), hash, KEY_SIZE);
            SHA256_Final(hash, ctx.get());
        }
        
        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), pw.c_str(), pw.size());
        SHA256_Update(ctx.get(), hash, KEY_SIZE);
        SHA256_Update(ctx.get(), pw.c_str(), pw.size());
        SHA256_Final(hash, ctx.get()); 

        AES_set_encrypt_key(hash, 256, &keys->ekey);
        AES_set_decrypt_key(hash, 256, &keys->dkey);
    }


    void encrypt(char *in, char *out, Context_t &ctx) {
        char tmp[BLOCK_SIZE];
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            tmp[i] = ctx.block[i] ^ in[i];
        }
        AES_encrypt((unsigned char *)tmp, (unsigned char *)out, &keys->ekey);
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            ctx.block[i] = out[i] ^ in[i];
        }
    }

    void decrypt(char *in, char *out, Context_t &ctx) {
        AES_decrypt((const unsigned char *)in, (unsigned char *)out, &keys->dkey);
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            out[i] ^= ctx.block[i];
        }
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            ctx.block[i] = out[i] ^ in[i];
        }
    }


private:
    SafePtr_t<Secret_t> keys;
    Seed_t seed;
};



int main(int argc, char **argv) {
    char *ptmp = getpass("Enter password:");
    Password_t pass(ptmp);
    size_t sz = strlen(ptmp);
    memset(ptmp, 0, sz);
    ptmp = getpass("Re-enter password:");

    if (strcmp(ptmp, pass.c_str())) {
        std::cout << "err: don't match" << std::endl;
        size_t sz = strlen(ptmp);
        memset(ptmp, 0, sz);
        return 1;
    }

    AES_t aes;
    aes.init(pass);

    const char * text = ".....................a.........................";

    char buf[AES_t::BLOCK_SIZE * 5];

    memset(buf, 0, sizeof(buf));
    memcpy(buf, text, sizeof(buf));

    AES_t::Context_t ctxe;
    AES_t::Context_t ctxd;

    char *c = buf;
    for (int i = 0; i<5; i++) {
        aes.encrypt(c, c, ctxe);
        c += AES_t::BLOCK_SIZE;
    }

    std::cout << s28::hex(buf, sizeof(buf)) << std::endl;

    c = buf;
    for (int i = 0; i<5; i++) {
        aes.decrypt(c, c, ctxd);
        c += AES_t::BLOCK_SIZE;
    }

    std::cout << buf << std::endl;


    return 0;
}




