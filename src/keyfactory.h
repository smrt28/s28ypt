#ifndef S28_KEYFACTORY_H
#define S28_KEYFACTORY_H

#include "safemem.h"

namespace s28 {

template<typename Digest_t, typename Cypher_t, int iterations = 3000000>
class KeyFactory_t {
    typedef s28::SafePtr_t<char, Digest_t::DIGEST_LENGTH> Hash_t;
    typedef s28::SafePtr_t<char, Cypher_t::KEY_SIZE> Master_t;

    void expand(const Hash_t &_h, Master_t &res) {
        res.zero();
        Hash_t h;
        h.zero();
        Digest_t digest;
        typename Master_t::iterator mit = res.begin();
        typename Master_t::iterator meit = res.end();
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
    KeyFactory_t() {
        master.zero();
    }

    const Master_t & get() const {
        return master;
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
        Master_t tmp;
        expand(rawKey, tmp);
        master.exor(tmp);
    }

    template<typename IO_t>
    void addKeyFile(IO_t &fd) {
        char buf[4096];
        size_t rd;

        Digest_t digest;

        for (;;) {
            rd = fd.read(buf, sizeof(buf));
            digest.update(buf, rd);
            if (rd < sizeof(buf)) break;
        }
        Hash_t h;
        digest.finalize(h);
        Master_t tmp;
        expand(h, tmp);
        master.exor(tmp);
    }

private:
    Master_t master;
};

} // namespace s28
#endif
