

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


namespace errcode {
    static const int MLOCK = 1;
}


class Error_t : public std::exception {
public:
    Error_t(int code, const std::string &msg) :
        code(code), msg(msg)
    {}

    virtual ~Error_t() throw() {}

    const char* what() const throw() {
        return msg.c_str();
    }

    int value() const { return code; }
private:
    int code;
    std::string msg;
};




template<typename T_t, size_t CNT = 1>
class SafePtr_t {
public:
    SafePtr_t() : t(0) {
        t = (T_t *)malloc(size);
        if (mlock(t, size) != 0) {
            free(t);
            t = 0;
            throw Error_t(errcode::MLOCK, "mlock failed");
        }
    }

    ~SafePtr_t() {
        if (!t) return;
        zero();
        munlock(t, size);
        free(t);
    }

    void zero() {
        memset(t, 0, size);
    }

    T_t * get() { return t; }
    const T_t * get() const { return t; }

    static const size_t size = sizeof(T_t[CNT]);

private:
    T_t *t;
};

template<typename T_t>
void print_hex(T_t *_data, size_t len) {
    unsigned char *data = (unsigned char *)_data;
    const char *abc = "0123456789abcdef";
    for (;len;len--, data++) {
        std::cout << abc[*data & 0xf];
        std::cout << abc[(*data >> 4) & 0xf];
    }
    std::cout << std::endl;
}

void prepare_key(const char *pw, size_t pwlen) {
    SafePtr_t<SHA256_CTX> ctx;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(ctx.get());
    SHA256_Update(ctx.get(), pw, pwlen);
    SHA256_Final(hash, ctx.get()); 
    
   
    for (int i = 0; i < 3000000; ++i) {
        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), hash, sizeof(hash));
        SHA256_Final(hash, ctx.get());
    }
    
    SHA256_Init(ctx.get());
    SHA256_Update(ctx.get(), pw, pwlen);
    SHA256_Update(ctx.get(), hash, sizeof(hash));
    SHA256_Update(ctx.get(), pw, pwlen);
    SHA256_Final(hash, ctx.get()); 

    print_hex(hash, sizeof(hash));
}


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

class Context_t {
    static const size_t KEY_SIZE = SHA256_DIGEST_LENGTH;
public:
    static const size_t BLOCK_SIZE = AES_BLOCK_SIZE;
    void init(const Password_t &pw, bool enc) {
        SafePtr_t<unsigned char, KEY_SIZE> rawKey;
        SafePtr_t<SHA256_CTX> ctx;
        reset();
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

        print_hex(rawKey.get(), KEY_SIZE);

        AES_set_encrypt_key(rawKey.get(), 256, ekey.get());
        AES_set_decrypt_key(rawKey.get(), 256, dkey.get());
    }

    void reset() {
        memset(_block, 0, BLOCK_SIZE);
    }

    void encrypt(const char *in) {
        unsigned char tmp[BLOCK_SIZE];
        AES_encrypt((const unsigned char *)in, tmp, ekey.get());
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            _block[i] ^= tmp[i];
        }
    }

    void decrypt() {
        unsigned char tmp[BLOCK_SIZE];
        AES_decrypt(_block, tmp, dkey.get());
        print_hex(tmp, BLOCK_SIZE);
    }

    const unsigned char * block() {
        return _block;
    }

private:
    SafePtr_t<AES_KEY> ekey;
    SafePtr_t<AES_KEY> dkey;
    Seed_t seed;
    unsigned char _block[BLOCK_SIZE];
};

int main(int argc, char **argv) {

    std::cout << AES_BLOCK_SIZE << std::endl;

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

    Context_t ctx;
    ctx.init(pass, true);

    char buf[Context_t::BLOCK_SIZE];
    memset(buf, 0, sizeof(buf));
    buf[5] = 10;
    ctx.encrypt(buf);
    print_hex(ctx.block(), Context_t::BLOCK_SIZE);
    ctx.decrypt();

    return 0;
}




