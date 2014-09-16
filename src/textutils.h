#ifndef S28_TEXTUTILS_H
#define S28_TEXTUTILS_H

#include <string>

namespace s28 {

namespace aux {
std::string hex(void *, size_t len);
} // namespace aux


template<typename Ptr_t>
std::string hex(Ptr_t *p, size_t len) {
    return aux::hex((void *)p, len);
}

inline std::string hex(const std::string &s) {
    return hex(s.c_str(), s.size());
}

}

#endif
