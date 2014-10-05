#ifndef S28_CBC_H
#define S28_CBC_H

#include "safemem.h"

namespace s28 {

struct encrypt_t {};
struct decrypt_t {};

namespace detail {

template<bool>
class ECHelper_t;

template<>
class ECHelper_t<true> {
public:
    typedef encrypt_t Direction_t;
};

template<>
class ECHelper_t<false> {
public:
    typedef decrypt_t Direction_t;
};

}


template<typename Cypher_t, bool direction>
class CBC_t {
public:
    static const size_t BLOCK_SIZE = Cypher_t::BLOCK_SIZE;
    
    typedef Cypher_t BlockCypher_t;
    typedef char Block_t[BLOCK_SIZE];


    class Context_t {
    public:
        Context_t() {
            fill_zero(block);
        }
        Block_t block;
    };


    CBC_t(Cypher_t &cipher) :
        cipher(cipher)
    {}

    inline void process(char *in, char *out, Context_t &ctx) {
        _process(in, out, ctx,
                typename detail::ECHelper_t<direction>::Direction_t());
    }

private:
    inline void _process(char *in, char *out, Context_t &ctx, encrypt_t) {
        char tmp[BLOCK_SIZE];
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            tmp[i] = ctx.block[i] ^ in[i];
        }

        cipher.encrypt(tmp, out);

        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            ctx.block[i] = out[i] ^ in[i];
        }
    }

    inline void _process(char *in, char *out, Context_t &ctx, decrypt_t) {
        cipher.decrypt(in, out);
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            out[i] ^= ctx.block[i];
        }
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            ctx.block[i] = out[i] ^ in[i];
        }
    }

private:
    Cypher_t &cipher;
};

}
#endif
