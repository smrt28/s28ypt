#ifndef S28_ERROR_H
#define S28_ERROR_H

#include <string>
#include <exception>

namespace s28 {

namespace errcat {

}

namespace errcode {
    static const int MLOCK = 1;
    static const int ALLOC = 2;
	static const int INVALID_FD = 3;
	static const int READ = 4;
	static const int WRITE = 5;

	namespace serializer {
		static const int BOUNDS = 6;
	}
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
