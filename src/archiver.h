#ifndef S28_ARCHIVER_H
#define S28_ARCHIVER_H

#include <string.h>
#include <stdint.h>
#include <string>

#include "portable-endian.h"
#include "error.h"
#include "array.h"

namespace s28 {

template<typename Data_t>
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

    template<typename T_t, size_t SIZE>
    void put(const Array_t<T_t, SIZE> &a) {
        _put_array(a.begin(), a.end());
    }

    template<typename T_t, size_t SIZE>
    void put(const SafeArray_t<T_t, SIZE> &a) {
        _put_array(a.begin(), a.end());
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

    template<typename It_t>
    void _put_array(It_t it, It_t eit) {
        for (;it != eit;++it)
            _put(*it);
    }

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



template<typename Data_t>
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



template<typename T_t, typename Data_t>
Marshaller_t<Data_t> & operator<<(Marshaller_t<Data_t> &m, T_t val) {
    m.put(val);
    return m;
}

template<typename T_t, typename Data_t>
Demarshaller_t<Data_t> & operator>>(Demarshaller_t<Data_t> &d, T_t &val) {
    val = d. template get<T_t>();
    return d;
}

}

#endif
