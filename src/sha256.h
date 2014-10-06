#ifndef S28_SHA256_H
#define S28_SHA256_H
#include <openssl/sha.h>
#include "safemem.h"
#include <iostream>
namespace s28 {
class sha256_t {
public:
    static const size_t DIGEST_LENGTH = SHA256_DIGEST_LENGTH;

    sha256_t() {
        init();
    }

    void init() {
        SHA256_Init(ctx);
    }

    void update(const void *ptr, size_t size) {
		//std::cerr.write((const char *)ptr, size);
        SHA256_Update(ctx, ptr, size);
    }

    template<typename T_t>
    void finalize(SafePtr_t<T_t, DIGEST_LENGTH> &ptr) {
        finalize(ptr.get());
    }

    template<typename T_t>
    void finalize(T_t *ptr) {
        SHA256_Final((unsigned char *)ptr, ctx);
    }

private:
    s28::SafePtr_t<SHA256_CTX> ctx;    
};

};

#endif

