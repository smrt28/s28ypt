#ifndef S28_SAFEMEM_H
#define S28_SAFEMEM_H

#include <stdlib.h>
#include <string.h>
namespace s28 {

void * safe_malloc(size_t);
void safe_free(void *);

void fill_random(void *, size_t);

template<typename T_t>
void fill_random(T_t &t) {
    fill_random(&t, sizeof(t));
}

template<typename T_t>
void fill_zero(T_t &t) {
    memset(&t, 0, sizeof(t));
}

}

#endif
