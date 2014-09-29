

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include <stdlib.h>
#include <sys/mman.h>

#include <string>
#include <exception>
#include <iostream>
#include <algorithm>
#include <openssl/rand.h>


#include "safemem.h"
#include "textutils.h"
#include "portable-endian.h"
#include "file.h"
#include "cbc.h"
#include "aes.h"
#include "archiver.h"
#include "error.h"
static const int MASTER_KEY_SIZE = 32;


class Password_t {
public:
    Password_t() {}

    const char * get() const {
        return (char *)master.get();
    }

    void init(const char *pass) {
        s28::SafePtr_t<unsigned char, SHA256_DIGEST_LENGTH> rawKey;
        s28::SafePtr_t<SHA256_CTX> ctx;
        unsigned char *hash = rawKey.get();
        size_t len = strlen(pass);
        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), pass, len);
        SHA256_Final(hash, ctx.get());

        for (int i = 0; i < 3000000; ++i) {
            SHA256_Init(ctx.get());
            SHA256_Update(ctx.get(), hash, SHA256_DIGEST_LENGTH);
            SHA256_Final(hash, ctx.get());
        }

        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), pass, len);
        SHA256_Update(ctx.get(), hash, SHA256_DIGEST_LENGTH);
        SHA256_Update(ctx.get(), pass, len);
        SHA256_Final(hash, ctx.get());
        master.zero();
        memcpy(master.get(), rawKey.get(),
                std::min(SHA256_DIGEST_LENGTH, MASTER_KEY_SIZE));
    }

private:
    s28::SafePtr_t<unsigned char, MASTER_KEY_SIZE> master;
};


template<bool direction, typename IO_t, typename Cipher_t, typename Context_t>
class crypt_control_t {};


template<typename IO_t, typename Cipher_t, typename Context_t>
class crypt_control_t<true, IO_t, Cipher_t, Context_t> {
public:
    uint64_t filesize;
    void handle(Cipher_t &cipher,
            Context_t &ctx,
            IO_t &in,
            IO_t &out) 
    {
        char seed[Cipher_t::BLOCK_SIZE];
        char buf[Cipher_t::BLOCK_SIZE];
        s28::fill_random(seed);
        cipher.process(seed, buf, ctx);
        out.write(buf, Cipher_t::BLOCK_SIZE);

        s28::Data_t header(Cipher_t::BLOCK_SIZE);
        header.zero();
        s28::Marshaller_t m(header);
        filesize = in.size();
        m << filesize;
        m << uint32_t(0x0A280B28);
        size_t ds = m.data_size();

        if (ds > Cipher_t::BLOCK_SIZE) {
            s28::raise<s28::errcode::IMPOSSIBLE>("header doesn't fit block");
        }

        cipher.process(header.begin(), buf, ctx);
        out.write(buf, Cipher_t::BLOCK_SIZE);
    }

    void write(IO_t &io, void *buf, size_t count) {
        io.write(buf, count);
    }

};

template<typename IO_t, typename Cipher_t, typename Context_t>
class crypt_control_t<false, IO_t, Cipher_t, Context_t> {
public:
    uint64_t filesize;
    uint64_t rem;
    void handle(Cipher_t &cipher,
            Context_t &ctx,
            IO_t &in,
            IO_t &/*out*/) 
    {
        char buf[s28::AES_t::BLOCK_SIZE];
        char tmp[s28::AES_t::BLOCK_SIZE];
        
        in.read(buf, s28::AES_t::BLOCK_SIZE);
        cipher.process(buf, tmp, ctx);

        s28::Data_t header(Cipher_t::BLOCK_SIZE);
        in.read(buf, s28::AES_t::BLOCK_SIZE);
        cipher.process(buf, header.begin(), ctx);

        s28::Demarshaller_t dm(header);
        dm >> filesize;
        uint32_t magic;
        dm >> magic;
        if (magic != 0x0A280B28) {
            s28::raise<s28::errcode::INVALID_MAGIC>("invalid password"
                    " or not s28ypted");
        }
        rem = filesize;
    }

    void write(IO_t &io, void *buf, size_t count) {
        if (rem >= count) {
            rem -= count;
            io.write(buf, count);
            return;
        }
        io.write(buf, rem);
        rem = 0;
    }
};


template<bool direction>
void process_file(s28::AES_t &_aes,
        s28::FD_t &fdin,
        s28::FD_t &fdout)
{
    typedef s28::CBC_t<s28::AES_t, direction> Cipher_t;
    typedef typename Cipher_t::Context_t Context_t;
    Cipher_t aes(_aes);
    typedef s28::FD_t IO_t;

	char buf[256];
	char obuf[256];
    s28::fill_zero(buf);
    s28::fill_zero(obuf);


    Context_t ctx;
    crypt_control_t<direction, IO_t, Cipher_t, Context_t> ctl;

    ctl.handle(aes, ctx, fdin, fdout);


	for (;;) {
		ssize_t rd = fdin.read(buf, sizeof(buf));
		if (rd == 0) break;
		size_t blocks = rd / s28::AES_t::BLOCK_SIZE;
		size_t rem = rd % s28::AES_t::BLOCK_SIZE;
		if (rem) blocks++;

		char *in = buf, *out = obuf;
		for (size_t i = 0; i < blocks; i++) {
			aes.process(in, out, ctx);
			in += s28::AES_t::BLOCK_SIZE;
			out += s28::AES_t::BLOCK_SIZE;
		}
		ctl.write(fdout, obuf, out - obuf);
	}
}



template<bool direction>
void process_file(s28::AES_t &_aes,
        const std::string &inFile,
        const std::string &outFile)
{
    typedef s28::CBC_t<s28::AES_t, direction> Cipher_t;
    Cipher_t aes(_aes);

    typedef s28::FD_t IO_t;

	s28::FD_t fdin;
	s28::FD_t fdout;

	mode_t mode = S_IRUSR | S_IWUSR;
	fdin.set(open(inFile.c_str(), O_RDONLY));
	fdout.set(open(outFile.c_str(), O_WRONLY | O_CREAT, mode));

    process_file<direction>(_aes, fdin, fdout);
}



int _main(int argc, char **argv) {
    if (argc != 4) {
        std::cerr << "err: args" << std::endl;
        return -1;
    }
    
    char *ptmp = getpass("Enter password:");
    size_t sz = strlen(ptmp);
    s28::SafePtr_t<char, 128 + 1> rawpass;
    strcpy(rawpass.get(), ptmp);
    memset(ptmp, 0, sz);

    ptmp = getpass("Re-enter password:");

    if (strcmp(ptmp, rawpass.get()) != 0) {
        std::cout << "err: doesn't match" << std::endl;
        size_t sz = strlen(ptmp);
        memset(ptmp, 0, sz);
        return 1;
    }

    memset(ptmp, 0, sz);

    Password_t pass;
    pass.init(rawpass.get());
   
    s28::AES_t aes;
    aes.init(pass.get());

    if (std::string(argv[1]) == "-e") {
        process_file<true>(aes, argv[2], argv[3]);
    } else if (std::string(argv[1]) == "-d") {
        process_file<false>(aes, argv[2], argv[3]);
    } else {
        std::cerr << "err: args" << std::endl;
    }

	return 0;
}



int main(int argc, char **argv) {
	try {
		_main(argc, argv);
	} catch(const std::exception &e) {
		std::cerr << "err: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}


