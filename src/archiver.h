#ifndef S28_ARCHIVER_H
#define S28_ARCHIVER_H

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

    Array_t(size_t len = 16) :
        _size(len),
        _data(new Type_t[len])
    {}

    virtual ~Array_t() {
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


typedef Array_t<char> Data_t;

class Marshaller_t {
public:
    Marshaller_t(Data_t &data) :
        _data(data),
        ofs(data.begin())
    {}

    template<typename T_t>
    void put(T_t val) {
        _put(val);
    }

    size_t data_size() {
        return ofs - _data.begin();
    }

private:
    void _put(uint64_t val) { put_raw(htole64(val)); }
    void _put(uint32_t val) { put_raw(htole32(val)); }
    void _put(uint16_t val) { put_raw(htole16(val)); }
    void _put(uint8_t val) { put_raw(val); }

    void _put(int64_t val) { put_raw(htole64(val)); }
    void _put(int32_t val) { put_raw(htole32(val)); }
    void _put(int16_t val) { put_raw(htole16(val)); }
    void _put(int8_t val) { put_raw(val); }


    void _put(const std::string &s) {
        put<uint16_t>(static_cast<uint16_t>(s.size()));
        put_raw(s.data(), s.size());
    }

    template<typename T_t>
    void put_raw(const T_t &val) {
        put_raw(&val, sizeof(T_t));
    }

    template<typename T_t>
    void put_raw(const T_t *_ptr, size_t len) {
        const char *ptr = reinterpret_cast<const char *>(_ptr);
        if (ofs + len > _data.end()) {
            size_t newLen = (ofs + len) - _data.begin();
            size_t idx = ofs - _data.begin();
            _data.resize(newLen + newLen / 2);
            ofs = _data.begin() + idx;
        }
        memcpy(ofs, ptr, len);
        ofs += len;
    }

private:
    Data_t &_data;
    char * ofs;
};



class Demarshaller_t {
public:
    Demarshaller_t(Data_t &data) :
        _data(data),
        ofs(data.begin())
    {}

    template<typename T_t>
    T_t get() {
        T_t val;
        _get(val);
        return val;
    }

private:
    void _get(uint64_t &val) { val = le64toh(get_raw<uint64_t>()); }
    void _get(uint32_t &val) { val = le32toh(get_raw<uint32_t>()); }
    void _get(uint16_t &val) { val = le16toh(get_raw<uint16_t>()); }
    void _get(uint8_t &val) { val = get_raw<uint8_t>(); }

    void _get(int64_t &val) { val = le64toh(get_raw<int64_t>()); }
    void _get(int32_t &val) { val = le32toh(get_raw<int32_t>()); }
    void _get(int16_t &val) { val = le16toh(get_raw<int16_t>()); }
    void _get(int8_t &val) { val = get_raw<int8_t>(); }


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

    void check(size_t len) {
        if (ofs + len > _data.end()) {
            raise<errcode::BOUNDS>("out of bounds");
        }
    }

private:
    Data_t &_data;
    char * ofs;
};

template<typename T_t>
Marshaller_t & operator<<(Marshaller_t &m, T_t val) {
    m.put(val);
    return m;
}

template<typename T_t>
Demarshaller_t & operator>>(Demarshaller_t &d, T_t &val) {
    val = d.get<T_t>();
    return d;
}

}

#if 0
int main() {
    try {
        s28::Data_t data(1);
        s28::Marshaller_t m(data);
        m << 1 << 2 << 3 << 4 << "ahojahojahojxxxxxxxxxxxxxxxxxxxxxxxxxxxx.";
        int32_t a[5];

        s28::Demarshaller_t d(data);
        std::string s;
        d >> a[0] >> a[1] >> a[2] >> a[3] >> s;

        std::cout << a[0] << std::endl;
        std::cout << a[1] << std::endl;
        std::cout << a[2] << std::endl;
        std::cout << a[3] << std::endl;
        std::cout << s << std::endl;
    } catch(const std::exception &e) {
        std::cout << "err: " << e.what() << std::endl;
    }
    return 0;
}
#endif

#endif
