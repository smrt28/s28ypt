#ifndef S28_CHECKS_H
#define S28_CHECKS_H

#include "error.h"
namespace s28 {

template<typename It_t>
bool only_zeros(It_t it, It_t eit) {
    for (;it != eit; ++it)  {
        if (*it != 0) return false;
    }
    return true;
}

}

#endif
