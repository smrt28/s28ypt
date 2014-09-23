#ifndef S28_ERROR_H
#define S28_ERROR_H

#include <stdint.h>

#include <string>
#include <exception>

#include "errorcodes.h"

namespace s28 {

class BaseError_t : public std::exception {
public:
    virtual int code() const = 0;
    virtual int category() const = 0;
};

class Error_t : public BaseError_t {
public:
    Error_t(const std::string &msg) :
        msg(msg)
    {}

    virtual ~Error_t() throw() {}

    const char* what() const throw() {
        return msg.c_str();
    }

private:
    std::string msg;
};


template<int _category>
class ErrorByCategory_t : public BaseError_t {};

template<int _code>
class ErrorByCode_t : public BaseError_t {};

namespace aux {
template<typename EC_t>
class Error_t :
    public s28::Error_t,
    public ErrorByCategory_t<EC_t::CATEGORY>,
    public ErrorByCode_t<EC_t::CODE>
{
public:
    Error_t(const std::string &msg) :
        s28::Error_t(msg)
    {}
    int category() const {
        return EC_t::CATEGORY;
    }
    int code() const {
        return EC_t::CODE;
    }
};
}


template<typename Code_t>
void raise(const std::string &msg) {
    throw aux::Error_t<Code_t>(msg);
}


}

#endif
