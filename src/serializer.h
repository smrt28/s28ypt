#ifndef S28_SERIALIZER_H
#define S28_SERIALIZER_H

#include <string.h>
#include <stdint.h>
#include <string>

#include "portable-endian.h"
#include "error.h"

namespace s28 {

template<typename Type_t>
class Array_t {
public:
    typedef Type_t value_type;

    Array_t(size_t len) :
        _size(len),
        _data(new Type_t[len])
    {}

    virtual ~Array_t() {
        delete [] _data;
    }

    size_t size() const {
        return _size;
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

class Serializer_t {
public:
    Serializer_t(size_t len) :
        _data(len),
        ofs(_data.begin())    {}


    template<typename T_t>
    T_t get() {
        T_t val;
        _get(val);
        return val;
    }

    template<typename T_t>
    void put(T_t val) {
        _put(val);
    }

    void reset() {
        ofs = _data.begin();
    }

private:
    void _put(uint64_t val) {
        put_raw(htole64(val));
    }

    void _put(uint32_t val) {
        put_raw(htole32(val));
    }

    void _put(uint16_t val) {
        put_raw(htole16(val));
    }

    void _put(uint8_t val) {
        put_raw(val);
    }

    void _put(const std::string &s) {
        put<uint16_t>(static_cast<uint16_t>(s.size()));
        put_raw(s.data(), s.size());
    }


    void _get(uint64_t &val) {
        val = le64toh(get_raw<uint64_t>());
    }

    void _get(uint32_t &val) {
        val = le32toh(get_raw<uint32_t>());
    }

    void _get(uint16_t &val) {
        val = le16toh(get_raw<uint16_t>());
    }

    void _get(uint8_t &val) {
        val = get_raw<uint8_t>();
    }

    void _get(std::string &s) {
        uint16_t sz = get<uint16_t>();
        check(sz);
        char buf[sz + 1];
        memcpy(buf, ofs, sz);
        buf[sz] = 0;
        s = buf;
    }


    template<typename T_t>
    T_t get_raw() {
        static const size_t len = sizeof(T_t);
        check(len);
        T_t rv;
        memcpy(&rv, ofs, len);
        ofs += len;
        return rv;
    }

    template<typename T_t>
    void put_raw(const T_t &val) {
        put_raw(&val, sizeof(T_t));
    }

    template<typename T_t>
    void put_raw(const T_t *_ptr, size_t len) {
        const char *ptr = reinterpret_cast<const char *>(_ptr);
        check(len);
        memcpy(ofs, ptr, len);
        ofs += len;
    }

    void check(size_t len) {
        if (ofs + len > _data.end()) {
            throw Error_t(errcode::serializer::BOUNDS,
                    "out of bounds");
        }
    }

private:
    Array_t<char> _data;
    char * ofs;
};

}

#endif
