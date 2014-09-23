

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
class handle_header_t {
public:
//    static void foo() {}
};


template<typename IO_t, typename Cipher_t, typename Context_t>
class handle_header_t<true, IO_t, Cipher_t, Context_t> {
public:
    static void handle(Cipher_t &cipher, Context_t &ctx, IO_t &/*in*/, IO_t &out) {
        char seed[Cipher_t::BLOCK_SIZE];
        char seedout[Cipher_t::BLOCK_SIZE];
        s28::fill_random(seed);
        cipher.process(seed, seedout, ctx);
        out.write(seedout, Cipher_t::BLOCK_SIZE);
        //handle_header_t<false, IO_t, Cipher_t, Context_t>::foo();
    }
};



void encrypt_file(s28::AES_t &_aes,
        const std::string &inFile,
        const std::string &outFile)
{
    typedef s28::CBC_t<s28::AES_t, true> Cipher_t;
    typedef Cipher_t::Context_t Context_t;
    Cipher_t aes(_aes);

    typedef s28::FD_t IO_t;

	s28::FD_t fdin;
	s28::FD_t fdout;

	mode_t mode = S_IRUSR | S_IWUSR;
	fdin.set(open(inFile.c_str(), O_RDONLY));
	fdout.set(open(outFile.c_str(), O_WRONLY | O_CREAT, mode));

	char buf[256];
	char obuf[256];
    s28::fill_zero(buf);
    s28::fill_zero(obuf);

    Context_t ctx;

    handle_header_t<true, IO_t, Cipher_t, Context_t>::
        handle(aes, ctx, fdin, fdout);
    
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
		fdout.write(obuf, out - obuf);
	}
}

void decrypt_file(s28::AES_t &_aes,
        const std::string &inFile,
        const std::string &outFile)
{
    typedef s28::CBC_t<s28::AES_t, false> Cipher_t;
    typedef Cipher_t::Context_t Context_t;

    Cipher_t aes(_aes);


	s28::FD_t fdin;
	s28::FD_t fdout;

	mode_t mode = S_IRUSR | S_IWUSR;
	fdin.set(open(inFile.c_str(), O_RDONLY));
	fdout.set(open(outFile.c_str(), O_WRONLY | O_CREAT, mode));

	char buf[256];
	char obuf[256];

    s28::fill_zero(buf);
    s28::fill_zero(obuf);

    Context_t ctx;
    {
    char seed[s28::AES_t::BLOCK_SIZE];
    char tmp[s28::AES_t::BLOCK_SIZE];
    fdin.read(seed, s28::AES_t::BLOCK_SIZE);
    aes.process(seed, tmp, ctx);
    }


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
		fdout.write(obuf, out - obuf);
	}
}





int _main(int argc, char **argv) {
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
	encrypt_file(aes, "/etc/passwd", "/tmp/passwd.s28");
	decrypt_file(aes, "/tmp/passwd.s28", "/tmp/passwd.out");
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


