#include "textutils.h"

namespace s28 {
namespace aux {

std::string hex(void *_data, size_t len) {
    unsigned char *data = (unsigned char *)_data;
    const char *abc = "0123456789abcdef";
	char buf[(len * 2) + 1];
	buf[len * 2] = 0;
    for (size_t j=0;len;len--, data++) {
        buf[j++] = abc[*data & 0xf];
        buf[j++] = abc[(*data >> 4) & 0xf];		
    }
	return std::string(buf);
}

}
}
