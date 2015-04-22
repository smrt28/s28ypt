#ifndef S28_ERROR_H
#define S28_ERROR_H

#include <stdint.h>

#include <string>
#include <exception>
#include <sstream>

#include "errorcodes.h"

namespace s28 {

class BaseError_t {
public:
    virtual ~BaseError_t() {}
    virtual int code() const = 0;
    virtual int category() const = 0;
    virtual const char* what() const throw() = 0;
};



template<int _category>
class ErrorByCategory_t : public BaseError_t {};

template<int _code>
class ErrorByCode_t : public BaseError_t {};



template<typename EC_t>
class Error_t :
    public std::exception,
    public ErrorByCategory_t<EC_t::CATEGORY>,
    public ErrorByCode_t<EC_t::CODE>
{
public:
    Error_t(const std::string &msg) :
        msg(msg)
    {}

    virtual ~Error_t() throw() {}
    int category() const {
        return EC_t::CATEGORY;
    }
    int code() const {
        return EC_t::CODE;
    }

    const char* what() const throw() {
        return msg.c_str();
    }
private:
    std::string msg;
};


template<typename Code_t>
void raise(const std::string &msg = std::string()) {
    throw Error_t<Code_t>(msg);
}


template<typename Code_t>
class raiser_t {
public:
    raiser_t() {}

    template<typename T_t>
    raiser_t & operator << (T_t t) {
        oss << t;
        return *this;
    }

    void raise() {
        s28::raise<Code_t>(oss.str());
    }
    
    std::ostringstream oss;
};




}

#endif
