

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
#include "sha256.h"
#include "header28.h"


template<typename Digest_t, typename Cypher_t, int iterations = 3000000>
class Password_t {
    typedef s28::SafePtr_t<char, Digest_t::DIGEST_LENGTH> Hash_t;
    typedef s28::SafePtr_t<char, Cypher_t::KEY_SIZE> Master_t;

public:
    Password_t() {}

    const char * get() const {
        return (char *)master.get();
    }

    void expand(const Hash_t &_h) {
        master.zero();
        Hash_t h;
        h.zero();
        Digest_t digest;
        typename Master_t::iterator mit = master.begin();
        typename Master_t::iterator meit = master.end();
        for (;;) {
            digest.init();
            digest.update(_h);
            digest.update(h);
            digest.update(_h);
            digest.finalize(h);
            for (typename Hash_t::const_iterator it = h.begin(),
                    eit = h.end(); it != eit; ++it) 
            {
                if (mit == meit) return;
                *mit = *it;
                mit++;
            }
        }
    }

    void init(const char *pass) {
        Digest_t digest;
        Hash_t rawKey;
        size_t len = strlen(pass);
        digest.update(pass, len);
        digest.finalize(rawKey);

        for (int i = 0; i < iterations; ++i) {
            digest.init();
            digest.update(rawKey);
            digest.finalize(rawKey);
        }

        digest.init();
        digest.update(pass, len);
        digest.update(rawKey);
        digest.update(pass, len);
        digest.finalize(rawKey);
        expand(rawKey);
    }

private:
    Master_t master;
};



template<typename Cypher_t, typename IN_t, typename OUT_t, bool direction>
void process_file(Cypher_t &aes,
        IN_t &fdin,
        OUT_t &fdout)
{
    typedef typename Cypher_t::Context_t Context_t;
//    typedef s28::FD_t IO_t;

	char buf[4096];
	char obuf[4096];
    s28::fill_zero(buf);
    s28::fill_zero(obuf);

    Context_t ctx;

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


template<typename Digest_t, typename IO_t, bool direction>
class MAC_t {
public:
    MAC_t(Digest_t &digest, IO_t &io, ssize_t fsize = -1) :
        digest(digest),
        io(io),
        fsize(fsize)
    {}

    ssize_t read(void *buf, size_t len) {
        ssize_t rv = io.read(buf, len);
        if (direction && rv > 0) {
            digest.update(buf, rv);
        }
        return rv;
    }

    ssize_t write(void *buf, size_t len) {
        if (fsize == 0) return 0;
        if (fsize > 0) {
            if (len > fsize) len = fsize;            
            fsize -= len;
        }
        if (!direction) digest.update(buf, len);
        return io.write(buf, len);
    }

private:
    Digest_t &digest;
    IO_t &io;
    ssize_t fsize;
};


namespace aux {

template<typename Cypher_t, typename Input_t, typename Output_t>
void encrypt(Cypher_t &cyp, Input_t &in, Output_t &out) {
    process_file<Cypher_t, Input_t, Output_t, true>(cyp, in, out);
}

template<typename Cypher_t, typename Input_t, typename Output_t>
void decrypt(Cypher_t &cyp, Input_t &in, Output_t &out) {
    process_file<Cypher_t, Input_t, Output_t, false>(cyp, in, out);
}


}


template<typename BlockCypher_t, typename Ptr_t>
void randomize_with_cypher(BlockCypher_t &bc, Ptr_t &ptr) {
    ptr.random();

    typedef s28::SafeArray_t<char, BlockCypher_t::BLOCK_SIZE> Block_t;
    Block_t block1;
    Block_t block2;
    block1.random();


    for(typename Ptr_t::iterator it = ptr.begin(), eit=ptr.end();;)
    {
        bc.encrypt(block1, block2);
        block1.swap(block2);

        for(typename Block_t::iterator 
                bit = block1.begin(), beit = block1.end();
                bit != beit; ++bit)
        {
            *it ^= *bit;
            ++it;
            if (it == eit) return;
        }
    }
}

template<typename Cypher_t>
void process_mem(Cypher_t &cyp, char * in, char * out, size_t size) {
    typename Cypher_t::Context_t ctx;
    while(size) {
        if (size < Cypher_t::BLOCK_SIZE) return;
        cyp.process(in, out, ctx);
        in += Cypher_t::BLOCK_SIZE;
        out += Cypher_t::BLOCK_SIZE;
        size -= Cypher_t::BLOCK_SIZE;
    }
}


template<bool direction>
void process_file(s28::AES_t &__aes,
        const std::string &inFile,
        const std::string &outFile)
{
    static const size_t HEADER_SIZE = 256;
    typedef s28::SafeArray_t<char, HEADER_SIZE> Header_t;


    typedef s28::AES_t BlockCypher_t;
    typedef s28::CBC_t<BlockCypher_t, direction> Cypher_t;

    typedef s28::FD_t IO_t;
    typedef s28::sha256_t Digest_t;

	
    IO_t fdin;
	IO_t fdout;

	mode_t mode = S_IRUSR | S_IWUSR;
	fdin.set(open(inFile.c_str(), O_RDONLY));
    fdout.set(open(outFile.c_str(), O_WRONLY | O_CREAT, mode));
    if (direction) {
        s28::SafeArray_t<char, BlockCypher_t::KEY_SIZE> master;
        randomize_with_cypher(__aes, master);
        BlockCypher_t masterblock;
        masterblock.init(master.get());
        Cypher_t cyp(masterblock);
        Digest_t digest;
        uint64_t fsize = fdin.size();
        MAC_t<Digest_t, IO_t, direction> min(digest, fdin, fsize);
        Header_t header;
        header.zero();
        
        fdout.write(header.get(), Header_t::SIZE);

        aux::encrypt(cyp, min, fdout);

        s28::Marshaller_t<Header_t> m(header);

        s28::SafeArray_t<char, BlockCypher_t::BLOCK_SIZE> seed;
        seed.random();


        m.put(seed); // seed
        m << uint16_t(0x1); // version
        m << uint16_t(0x2828); // magic
        m.put(master); // master key
        m << fsize; // file size
        s28::Array_t<char, Digest_t::DIGEST_LENGTH> hash;
        digest.finalize(hash.get());
        m.put(hash); // hash
        Header_t headerEnc;
        Cypher_t hcyp(__aes);
        process_mem(hcyp, header.get(), headerEnc.get(), Header_t::SIZE);
        fdout.seek(0);
        fdout.write(headerEnc.get(), Header_t::SIZE);


    } else {
        Cypher_t cyp(__aes);
        Header_t encHeader;
        encHeader.zero();
        fdin.read(encHeader.get(), Header_t::SIZE);
        Header_t header;
        process_mem(cyp, encHeader.get(), header.get(), Header_t::SIZE);
        //std::cout << s28::hex(header.get(), Header_t::SIZE) << std::endl;
        s28::Demarshaller_t<Header_t> d(header);
        s28::SafeArray_t<char, BlockCypher_t::BLOCK_SIZE> seed;
        s28::SafeArray_t<char, BlockCypher_t::KEY_SIZE> master;
        s28::Array_t<char, Digest_t::DIGEST_LENGTH> hash, hashres;
        d.get(seed);
        uint16_t tmp16;
        d >> tmp16; // version
        if (tmp16 != 1) {
            s28::raise<s28::errcode::INVALID_VERSION>("version doesn't match");
        }
        
        //std::cout << tmp16 << std::endl;
        d >> tmp16; // magic
        
        if (tmp16 != 0x2828) {
            s28::raise<s28::errcode::INVALID_MAGIC>("wrong magic");
        }
        //std::cout << tmp16 << std::endl;

        d.get(master);
        uint64_t fsize;
        d >> fsize;
        d.get(hash);

        Digest_t digest;
        MAC_t<Digest_t, IO_t, direction> min(digest, fdout, fsize);
        // std::cout << s28::hex(master.get(), master.size()) << std::endl << std::endl;
        BlockCypher_t masterblock;
        masterblock.init(master.get());
        Cypher_t dcyp(masterblock);
        aux::decrypt(dcyp, fdin, min);
        digest.finalize(hashres.get());

        if (!hash.cmp(hashres)) {
            s28::raise<s28::errcode::INCONSISTENT>("broken data");
        }

        //std::cout << "h:" << s28::hex(hash.get(), hash.size()) << std::endl << std::endl;
        //std::cout << "h:" << s28::hex(hashres.get(), hashres.size()) << std::endl << std::endl;
    }
}

namespace aux {
char * getpass(const char *msg) {
    return ::getpass(msg);
}

}

int _main(int argc, char **argv) {
    typedef s28::AES_t Cypher_t;
    typedef s28::sha256_t Digest_t;

    if (argc != 4) {
        std::cerr << "err: args" << std::endl;
        return -1;
    }
    bool encrypt;
    if (std::string(argv[1]) == "-e") {
        encrypt = true;
    } else if (std::string(argv[1]) == "-d") {
        encrypt = false;
    } else {
        std::cerr << "err: args" << std::endl;
        return 1;
    }
    
    char *ptmp = aux::getpass("Enter password:");
    size_t sz = strlen(ptmp);
    s28::SafePtr_t<char, 128 + 1> rawpass;
    strcpy(rawpass.get(), ptmp);
    memset(ptmp, 0, sz);

    if (encrypt) {
        ptmp = aux::getpass("Re-enter password:");

        if (strcmp(ptmp, rawpass.get()) != 0) {
            std::cout << "err: doesn't match" << std::endl;
            size_t sz = strlen(ptmp);
            memset(ptmp, 0, sz);
            return 1;
        }

        memset(ptmp, 0, sz);
    }

    Password_t<Digest_t, Cypher_t> pass;
    pass.init(rawpass.get());

    Cypher_t aes;
    aes.init(pass.get());

    if (encrypt) {
        process_file<true>(aes, argv[2], argv[3]);
    } else {
        process_file<false>(aes, argv[2], argv[3]);
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


