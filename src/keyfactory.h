#ifndef S28_KEYFACTORY_H
#define S28_KEYFACTORY_H

#include "safemem.h"

namespace s28 {

template<typename Digest_t, typename Cypher_t, int iterations = 3000000>
class KeyFactory_t {
    typedef s28::SafePtr_t<char, Digest_t::DIGEST_LENGTH> Hash_t;
    typedef s28::SafePtr_t<char, Cypher_t::KEY_SIZE> Master_t;

    void expand(const Hash_t &_h) {
        master.zero();
        Hash_t h;
        h.zero();
        Digest_t digest;
        typename Master_t::iterator mit = master.begin();
        typename Master_t::iterator meit = master.end();
        for (;;) {
            digest.init();
            digest.update(_h);
            digest.update(h);
            digest.update(_h);
            digest.finalize(h);
            for (typename Hash_t::const_iterator it = h.begin(),
                    eit = h.end(); it != eit; ++it)
            {
                if (mit == meit) return;
                *mit = *it;
                mit++;
            }
        }
    }

public:
    KeyFactory_t() {}

    const char * get() const {
        return (char *)master.get();
    }

    void init(const char *pass) {
        Digest_t digest;
        Hash_t rawKey;
        size_t len = strlen(pass);
        digest.update(pass, len);
        digest.finalize(rawKey);

        for (int i = 0; i < iterations; ++i) {
            digest.init();
            digest.update(rawKey);
            digest.finalize(rawKey);
        }

        digest.init();
        digest.update(pass, len);
        digest.update(rawKey);
        digest.update(pass, len);
        digest.finalize(rawKey);
        expand(rawKey);
    }

private:
    Master_t master;
};

} // namespace s28
#endif
