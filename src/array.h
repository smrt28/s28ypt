#ifndef S28_ARRAY_H
#define S28_ARRAY_H

#include "safemem.h"
#include "error.h"

namespace s28 {

template<typename Type_t>
class MutableArray_t {
public:
    typedef Type_t value_type;

    MutableArray_t(size_t len = 16) :
        _size(len),
        _data(new Type_t[len])
    {}

    virtual ~MutableArray_t() {
        delete [] _data;
    }

    size_t size() const {
        return _size;
    }

    void resize(size_t size) {
        if (size <= _size) return;
        Type_t * newData = new Type_t[size];
        memcpy(newData, _data, sizeof(Type_t[_size]));
        delete [] _data;
        _data = newData;
        _size = size;
    }

    void zero() {
        memset(_data, 0, _size);
    }

    Type_t * begin() { return _data; }
    Type_t * end() { return _data + _size; }

private:
    size_t _size;
    Type_t *_data;
};



template<typename Type_t, size_t SIZE>
class Array_t : public s28::SafePtr_t<Type_t, SIZE, s28_allocator_t> {
public:
    void resize(size_t) {
        raise<errcode::NOT_RESIZABLE>("resize not allowed");
    }
};

template<typename Type_t, size_t SIZE>
class SafeArray_t : public s28::SafePtr_t<Type_t, SIZE, safe_allocator_t> {
public:
    void resize(size_t) {
        raise<errcode::NOT_RESIZABLE>("resize not allowed");
    }
};

}
#endif
