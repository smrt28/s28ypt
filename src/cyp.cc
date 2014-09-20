

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <stdlib.h>
#include <sys/mman.h>

#include <string>
#include <exception>
#include <iostream>
#include <algorithm>
#include <openssl/rand.h>


#include "safemem.h"
#include "textutils.h"
#include "endian.h"

static const int MASTER_KEY_SIZE = 32;



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
    Password_t() {
    }
    
    size_t size() const {
        return MASTER_KEY_SIZE;
    }

    const unsigned char * get() const {
        return master.get();
    }

    void init(const char *pass) {
        SafePtr_t<unsigned char, SHA256_DIGEST_LENGTH> rawKey;
        SafePtr_t<SHA256_CTX> ctx;
        unsigned char *hash = rawKey.get();
        size_t len = strlen(pass);
        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), pass, len);
        SHA256_Final(hash, ctx.get()); 
       
        for (int i = 0; i < 300000; ++i) {
            SHA256_Init(ctx.get());
            SHA256_Update(ctx.get(), hash, SHA256_DIGEST_LENGTH);
            SHA256_Final(hash, ctx.get());
        }
        
        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), pass, len);
        SHA256_Update(ctx.get(), hash, SHA256_DIGEST_LENGTH);
        SHA256_Update(ctx.get(), pass, len);
        SHA256_Final(hash, ctx.get());
        master.zero();
        memcpy(master.get(), rawKey.get(),
                std::min(SHA256_DIGEST_LENGTH, MASTER_KEY_SIZE));
    }


private:
    SafePtr_t<unsigned char, MASTER_KEY_SIZE> master;
};



class AES_t {
    struct Secret_t {
        AES_KEY ekey;
        AES_KEY dkey;
    };

public:
    static const size_t BLOCK_SIZE = AES_BLOCK_SIZE;

    typedef char Block_t[BLOCK_SIZE];

    class Context_t {
    public:
        Context_t(void *seed = 0) {
            reset(seed);
        }
        void reset(void *seed = 0) {
            if (seed) {
                memcpy(block, seed, BLOCK_SIZE);
            } else {
                memset(block, 0, sizeof(block));
            }
            counter = 0;
        }
        Block_t block;
        uint64_t counter;
    };


    void init(const Password_t &pw) {
        AES_set_encrypt_key(pw.get(), 256, &keys->ekey);
        AES_set_decrypt_key(pw.get(), 256, &keys->dkey);
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
};

namespace s28 {
	void foo() ;
}

int _main(int argc, char **argv) {
	s28::foo();
	return 0;
    char *ptmp = getpass("Enter password:");
    size_t sz = strlen(ptmp);
    SafePtr_t<char, 128 + 1> rawpass;
    strcpy(rawpass.get(), ptmp);
    memset(ptmp, 0, sz);

    ptmp = getpass("Re-enter password:");

    if (strcmp(ptmp, rawpass.get()) != 0) {
        std::cout << "err: doesn't match" << std::endl;
        size_t sz = strlen(ptmp);
        memset(ptmp, 0, sz);
        return 1;
    }
    memset(ptmp, 0, sz);

    Password_t pass;
    pass.init(rawpass.get());

    AES_t aes;
    aes.init(pass);

    const char * text = ".....................a.........................";

    char buf[AES_t::BLOCK_SIZE * 5];

    memset(buf, 0, sizeof(buf));
    memcpy(buf, text, sizeof(buf));

    AES_t::Block_t seed;
    s28::fill_zero(seed);


    AES_t::Context_t ctxe(seed);
    AES_t::Context_t ctxd(seed);

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



int main(int argc, char **argv) {
	try {
		_main(argc, argv);
	} catch(const std::exception &e) {
		std::cerr << "err: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}


