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




}

#endif
