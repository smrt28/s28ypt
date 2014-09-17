#include <string.h>

#include <sys/mman.h>
#include <iostream>
#include <openssl/rand.h>

#include "safemem.h"
#include "error.h"

namespace s28 {

void * safe_malloc(size_t size) {
    void *rv = malloc(size + sizeof(size_t));
    if (rv == 0) {
        throw Error_t(errcode::ALLOC, "malloc failed");
    }
    if (mlock(rv, size + sizeof(size_t)) != 0) {
        free(rv);
        throw Error_t(errcode::MLOCK, "mlock failed");
    }

    *(size_t *)rv = size;
       
    return (size_t *)rv + 1;
}

void safe_free(void *p)  {
    size_t *s = (size_t *)p - 1;

    memset(s, 0, *s);

    if (munlock(s, *s) != 0) {
        std::cerr << "err: munlock failed" << std::endl;
    }
    free(s);
}

void fill_random(void *p, size_t size) {
    RAND_bytes((unsigned char *)p, (size_t)size);
}


} // namespace s28
