
namespace s28 {

class FD_t {
public:
    FD_t() : _fd(-1) {}
    ~FD_t();

    int release();
    void set(int fd);
    ssize_t read(void *buf, size_t len);
    ssize_t write(void *buf, size_t count);   

private:
    int _fd;
};

}

