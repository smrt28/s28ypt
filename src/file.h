
namespace s28 {

class FD_t {
public:
    FD_t() : _fd(-1) {}
    ~FD_t();

    int release();
    void set(int fd);
    ssize_t read(void *buf, size_t len);
    ssize_t write(void *buf, size_t count);
    off_t size();
    void close();

    enum Whence_t {
        SET_TO,
        FROM_CUR,
        FROM_END
    };


    off_t seek(off_t offset, Whence_t whence = SET_TO);

private:
    int _fd;
};


struct FileOpener_t {
    static void forRead(const std::string &fname, FD_t &fd);
    static void forWrite(const std::string &fname, FD_t &fd);
};


}

