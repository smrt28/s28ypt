

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

#include <vector>
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
#include "checks.h"
#include "keyfactory.h"


template<typename Cypher_t, typename IN_t, typename OUT_t, bool direction>
void process_file(Cypher_t &aes,
        IN_t &fdin,
        OUT_t &fdout)
{
    typedef typename Cypher_t::Context_t Context_t;

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
            if (ssize_t(len) > fsize) len = fsize;
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


template<template<typename, bool> class _Mode_t,
    typename _Cypher_t,
    typename _Digest_t>
struct S28Config_t {
public:

    typedef _Digest_t Digest_t;
    typedef _Cypher_t BlockCypher_t;
    typedef s28::SafePtr_t<char, BlockCypher_t::KEY_SIZE> DerivedKey_t;

    template<bool direction>
    struct def_t {
        typedef _Mode_t<_Cypher_t, direction> Cypher_t;
    };
};

typedef S28Config_t<s28::CBC_t, s28::AES_t, s28::sha256_t> E_t;

template<bool direction, typename Opener_t, typename Cfg_t>
void s28_file(const typename Cfg_t::DerivedKey_t &key,
        const std::string &inFile,
        const std::string &outFile)
{
    static const size_t HEADER_SIZE = 256;
    typedef s28::SafeArray_t<char, HEADER_SIZE> Header_t;

    typedef typename Cfg_t::BlockCypher_t BlockCypher_t;
    typedef typename Cfg_t::template def_t<direction>::Cypher_t Cypher_t;
    typedef typename Cfg_t::Digest_t Digest_t;

    typename Cfg_t::BlockCypher_t __aes;
    __aes.init(key.get());

    typedef s28::FD_t IO_t;

    IO_t fdin;
	IO_t fdout;

    Opener_t::forRead(inFile, fdin);
    Opener_t::forWrite(outFile, fdout);

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

        d >> tmp16; // magic

        if (tmp16 != 0x2828) {
            s28::raise<s28::errcode::INVALID_MAGIC>("wrong magic");
        }

        d.get(master);
        uint64_t fsize;
        d >> fsize;
        d.get(hash);

        if (!s28::only_zeros(d.offset(), d.end())) {
            s28::raise<s28::errcode::MALFORMED_HEADER>("wrong header padding");
        }

        Digest_t digest;
        MAC_t<Digest_t, IO_t, direction> min(digest, fdout, fsize);
        BlockCypher_t masterblock;
        masterblock.init(master.get());
        Cypher_t dcyp(masterblock);
        aux::decrypt(dcyp, fdin, min);
        digest.finalize(hashres.get());

        if (!hash.cmp(hashres)) {
            s28::raise<s28::errcode::INCONSISTENT>("broken data");
        }
    }
}

namespace aux {
char * getpass(const char *msg) {
    return ::getpass(msg);
}

}

struct Params_t {
    template<typename It_t>
    Params_t(It_t it, It_t eit) : encrypt(true) {
        char p = 0;
        int eset = 0;
        for(;it != eit;++it) {
            std::string val = *it;
            if (val == "-e") {
                encrypt = true;
                eset ++;
                continue;
            }
            if (val == "-d") {
                encrypt = false;
                eset ++;
                continue;
            }
            if (val == "-f") {
                p = 'f';
                continue;
            }

            if (p == 0) {
                if (ifile.empty()) {
                    ifile = *it;
                    continue;
                }
                if (ofile.empty()) {
                    ofile = *it;
                    continue;
                }
                s28::raise<s28::errcode::ARGS>("args");
            }

            if (p == 'f') {
                p = 0;
                keyfiles.push_back(*it);
            }
        }

        if (ifile.empty() || ofile.empty()
                || eset != 1) {
            s28::raise<s28::errcode::ARGS>("args");
        }
    }

    std::string ifile;
    std::string ofile;
    std::vector<std::string> keyfiles;
    bool encrypt;
};


template<typename KF_t, typename Opener_t, typename It_t>
void add_key_files(KF_t &kf, It_t it, It_t eit, Opener_t) {
    for (;it != eit;++it) {
        s28::FD_t fd;
        Opener_t::forRead(*it, fd);
        kf.addKeyFile(fd);
    }
}



int _main(int argc, char **argv) {
    typedef s28::AES_t Cypher_t;
    typedef s28::sha256_t Digest_t;


    Params_t params(argv + 1, argv + argc);


    char *ptmp = aux::getpass("Enter password:");
    size_t sz = strlen(ptmp);
    s28::SafePtr_t<char, 128 + 1> rawpass;
    strcpy(rawpass.get(), ptmp);
    memset(ptmp, 0, sz);

    if (params.encrypt) {
        ptmp = aux::getpass("Re-enter password:");

        if (strcmp(ptmp, rawpass.get()) != 0) {
            std::cout << "err: doesn't match" << std::endl;
            size_t sz = strlen(ptmp);
            memset(ptmp, 0, sz);
            return 1;
        }

        memset(ptmp, 0, sz);
    }

    s28::KeyFactory_t<Digest_t, Cypher_t> pass;
    pass.init(rawpass.get());

    add_key_files(pass, params.keyfiles.begin(),
            params.keyfiles.end(), s28::FileOpener_t());


    if (params.encrypt) {
        s28_file<true, s28::FileOpener_t, E_t>(pass.get(),
                params.ifile, params.ofile);
    } else {
        s28_file<false, s28::FileOpener_t, E_t>(pass.get(),
                params.ifile, params.ofile);
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
    std::cerr << "ok" << std::endl;
	return 0;
}


