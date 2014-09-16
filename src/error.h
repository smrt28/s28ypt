#ifndef S28_ERROR_H
#define S28_ERROR_H

#include <string>
#include <exception>

namespace s28 {

namespace errcode {
    static const int MLOCK = 1;
    static const int ALLOC = 2;
}

class Error_t : public std::exception {
public:
    Error_t(int code, const std::string &msg) :
        code(code), msg(msg)
    {}

    virtual ~Error_t() throw() {}

    const char* what() const throw() {
        return msg.c_str();
    }

    int value() const { return code; }
private:
    int code;
    std::string msg;
};

}

#endif
