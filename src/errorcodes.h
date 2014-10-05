#ifndef S28_ERRORCOES_H
#define S28_ERRORCOES_H

namespace s28 {

template<int category, int code>
class ErrorCode_t {
public:
    static const int CODE = code;
    static const int CATEGORY = category;
};


namespace errc {
    static const int MEMORY = 1;
    static const int IO = 2;
    static const int MARSHAL = 3;
	static const int INTERNAL = 4;
}

namespace errcode {
    // MEMORY category
    typedef ErrorCode_t<errc::MEMORY, 101> MLOCK;
    typedef ErrorCode_t<errc::MEMORY, 102> ALLOC;
    typedef ErrorCode_t<errc::MEMORY, 103> INVALID_FD;
    typedef ErrorCode_t<errc::MEMORY, 104> NOT_RESIZABLE;

    // IO category
    typedef ErrorCode_t<errc::IO, 200> READ;
    typedef ErrorCode_t<errc::IO, 201> WRITE;
    typedef ErrorCode_t<errc::IO, 202> STAT;
    typedef ErrorCode_t<errc::IO, 203> SEEK;

    // MARSHAL category
    typedef ErrorCode_t<errc::MARSHAL, 301> BOUNDS;

	typedef ErrorCode_t<errc::INTERNAL, 401> IMPOSSIBLE;
	typedef ErrorCode_t<errc::INTERNAL, 402> INVALID_MAGIC;
}

}

#endif
