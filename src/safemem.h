#ifndef S28_SAFEMEM_H
#define S28_SAFEMEM_H

#include <stdlib.h>

namespace s28 {

void * safe_malloc(size_t);
void safe_free(void *);

}

#endif
