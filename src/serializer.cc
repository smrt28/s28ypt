
#include <iostream>

#include "serializer.h"
#include "endian.h"

namespace s28 {

void foo() {
    Serializer_t sr(16 + 10);

    sr.put<uint64_t>(1234);
    sr.put<uint64_t>(4321);
    sr.put<std::string>("ahoj");

    sr.reset();

    std::cout << sr.get<uint64_t>() << std::endl;
    std::cout << sr.get<uint64_t>() << std::endl;
    std::cout << sr.get<std::string>() << std::endl;
}

}

