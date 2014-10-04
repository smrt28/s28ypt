#ifndef S28_SAFEMEM_H
#define S28_SAFEMEM_H

#include <stdlib.h>
#include <string.h>
#include "error.h"

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

struct safe_allocator_t {
    static void * alloc(size_t n) {
        return s28::safe_malloc(n);
    }

    static void free(void *ptr) {
        s28::safe_free(ptr);
    }
};


struct s28_allocator_t {
    static void * alloc(size_t n) {
        void * rv = ::malloc(n);
        if (rv) return rv;
        raise<errcode::ALLOC>("malloc failed");
        return 0;
    }

    static void free(void *ptr) {
        ::free(ptr);
    }
};



template<typename T_t, size_t CNT = 1,
    typename Allocator_t = safe_allocator_t>
class SafePtr_t {
public:
    static const size_t SIZE = CNT;
    static const size_t DATA_SIZE = sizeof(T_t[CNT]);

    typedef const T_t * const_iterator;
    typedef T_t * iterator;

    iterator begin() { return t; }
    iterator end() { return t + CNT; }
    const_iterator begin() const { return t; }
    const_iterator end() const { return t + CNT; }

    SafePtr_t() : t((T_t *)Allocator_t::alloc(DATA_SIZE))
    {}

    ~SafePtr_t() {
        Allocator_t::free((void *)t);
    }

    void zero() {
        memset(t, 0, DATA_SIZE);
    }

    void random() {
        fill_random((void *)t, DATA_SIZE);
    }

    T_t * get() { return t; }
    const T_t * get() const { return t; }


    T_t * operator->() {
        return t;
    }

    operator T_t * () {
        return t;
    }

    T_t & operator *() {
        return *t;
    }

    T_t & operator[](size_t idx) { return t[idx]; }
    const T_t & operator[](size_t idx) const { return t[idx]; }

    size_t size() const { return SIZE; } 
    size_t data_size() const { return DATA_SIZE; }

    void swap(SafePtr_t<T_t, CNT> &ptr) {
        T_t *tmp = t;
        t = ptr.t;
        ptr.t = tmp;
    }
private:
    // not copyable
    SafePtr_t & operator=(const SafePtr_t &);
    SafePtr_t(const SafePtr_t &);

    T_t *t;
};



}

#endif
