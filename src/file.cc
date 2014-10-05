#include <sys/stat.h>
#include <unistd.h>
#include <iostream>

#include "file.h"
#include "error.h"

namespace s28 {

static void check_fd(int fd) {
    if (fd < 0) {
        raise<errcode::INVALID_FD>("I/O error");
    }
}

FD_t::~FD_t() {
    close();
}

void FD_t::close() {
    if (_fd == -1) return;
    if (::close(_fd) < 0) {
        // nothing to do there
        std::cerr << "err: close" << std::endl;
    }
    _fd = -1;
}

void FD_t::set(int fd) {
    check_fd(fd);
    close();
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
       raise<errcode::READ>("read failed");
    }

    return rv;    
}


ssize_t FD_t::write(void *buf, size_t len) {
    check_fd(_fd);
    ssize_t rv = ::write(_fd, buf, len);
    if (rv < 0) {
       raise<errcode::WRITE>("write failed");
    }

    return rv;    
}

off_t FD_t::size() {
    struct stat st;
    check_fd(_fd);
    if (fstat(_fd, &st)) {
       raise<errcode::STAT>("write failed");
    }
    return st.st_size;
}

off_t FD_t::seek(off_t offset, Whence_t whence) {
    check_fd(_fd);
    off_t rv;
    int w;
    switch(whence) {
        case SET_TO:
            w = SEEK_SET;
            break;
        case FROM_CUR:
            w = SEEK_CUR;
            break;
        case FROM_END:
            w = SEEK_END;
            break;
        default:
            raise<errcode::SEEK>("unknown whence");
    }
    if ((rv = lseek(_fd, offset, w)) == -1) {
        raise<errcode::SEEK>("lseek failed");
    }
    return rv;
}


}

