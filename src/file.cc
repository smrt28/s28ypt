#include <iostream>
#include <unistd.h>


#include "file.h"
#include "error.h"

namespace s28 {

static void check_fd(int fd) {
    if (fd < 0) {
        throw Error_t(errcode::INVALID_FD, "I/O error");
    }
}

FD_t::~FD_t() {
    if (_fd == -1) return;
    if (::close(_fd) < 0) {
        // nothing to do there
        std::cerr << "err: close" << std::endl;
    }
    _fd = -1;
}

void FD_t::set(int fd) {
    check_fd(fd);
    _fd = fd;
}


int FD_t::release() {
    int rv = _fd;
    _fd = -1;
    return rv;
}

ssize_t FD_t::read(void *buf, size_t len) {
    check_fd(_fd);
    ssize_t rv = ::read(_fd, buf, len);
    if (rv < 0) {
       throw Error_t(errcode::READ, "read failed");
    }

    return rv;    
}


ssize_t FD_t::write(void *buf, size_t len) {
    check_fd(_fd);
    ssize_t rv = ::write(_fd, buf, len);
    if (rv < 0) {
       throw Error_t(errcode::WRITE, "read failed");
    }

    return rv;    
}

}

