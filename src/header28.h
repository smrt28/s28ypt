#ifndef S28_HEADER28_H
#define S28_HEADER28_H

#include "safemem.h"

namespace s28 {

template<typename Cypher_t, typename Digest_t>
class Header28_t {
public:
    static const size_t HEADER_SIZE = 512;
    typedef s28::SafeArray_t<char, HEADER_SIZE> Header_t;


    Header_t header;
};

}

#endif
