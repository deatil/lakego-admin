package mode

import (
    "bytes"
    "errors"
    "crypto/cipher"
)

// RFC 3394 section 2.2.3.1 Default Initial Value
var defaultIv = []byte{
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
};

// RFC 5649 section 3 Alternative Initial Value 32-bit constant
var defaultAiv = []byte{
    0xA6, 0x59, 0x59, 0xA6,
};

// Input size limit: lower than maximum of standards but far larger than
// anything that will be used in practice.
const WRAP_MAX = uint64(1) << 31

type wrap struct {
    b         cipher.Block
    blockSize int
    iv        []byte
}

func newWrap(b cipher.Block, iv []byte) *wrap {
    c := &wrap{
        b:         b,
        blockSize: b.BlockSize(),
        iv:        make([]byte, b.BlockSize()),
    }

    if iv == nil {
        iv = defaultIv
    }

    if len(iv) < 8 {
        panic("cryptobin/wrap: IV length must gt or equal 8 bytes")
    }

    copy(c.iv, iv)

    return c
}

type wrapEncrypter wrap

type wrapEncAble interface {
    NewWrapEncrypter(iv []byte) cipher.BlockMode
}

func NewWrapEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if wrap, ok := b.(wrapEncAble); ok {
        return wrap.NewWrapEncrypter(iv)
    }

    return (*wrapEncrypter)(newWrap(b, iv))
}

func (x *wrapEncrypter) BlockSize() int {
    return x.blockSize
}

/** Wrapping according to RFC 3394 section 2.2.1.
 *
 *  @param[in]  iv     IV value. Length = 8 bytes. NULL = use default_iv.
 *  @param[in]  src    Plaintext as n 64-bit blocks, n >= 2.
 *  @param[out] dst    Ciphertext. Minimal buffer length = (srclen + 8) bytes.
 *                     Input and output buffers can overlap if block function
 *                     supports that.
 */
func (x *wrapEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%8 != 0 {
        panic("cryptobin/wrap: input not full blocks")
    }

    if len(dst) < len(src)+8 {
        panic("cryptobin/wrap: output smaller than input")
    }

    iv := x.iv

    inlen := len(src)

    var A, R []byte
    var i, j, t int

    A = make([]byte, 16)

    if (((inlen & 0x7) != 0) || (inlen < 16) || (uint64(inlen) > WRAP_MAX)) {
        panic("cryptobin/wrap: invalid src")
    }

    t = 1
    copy(dst[8:], src)
    copy(A, iv[:8])

    for j = 0; j < 6; j++ {
        R = dst[8:]
        for i = 0; i < inlen; i, t, R = i+8, t+1, R[8:] {
            copy(A[8:], R[:8])

            x.b.Encrypt(A, A)

            A[7] ^= byte(t & 0xff)
            if t > 0xff {
                A[6] ^= byte((t >> 8) & 0xff)
                A[5] ^= byte((t >> 16) & 0xff)
                A[4] ^= byte((t >> 24) & 0xff)
            }

            copy(R, A[8:])
        }
    }

    copy(dst, A[:8])

    copy(x.iv, iv)
}

func (x *wrapEncrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/wrap: incorrect length IV")
    }

    copy(x.iv, iv)
}

type wrapDecrypter wrap

type wrapDecAble interface {
    NewWrapDecrypter(iv []byte) cipher.BlockMode
}

func NewWrapDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if wrap, ok := b.(wrapDecAble); ok {
        return wrap.NewWrapDecrypter(iv)
    }

    return (*wrapDecrypter)(newWrap(b, iv))
}

func (x *wrapDecrypter) BlockSize() int {
    return x.blockSize
}

/** Unwrapping according to RFC 3394 section 2.2.2, including the IV check.
 *  The first block of plaintext has to match the supplied IV, otherwise an
 *  error is returned.
 *
 *  @param[out] iv     IV value to match against. Length = 8 bytes.
 *                     NULL = use default_iv.
 *  @param[out] dst    Plaintext without IV.
 *                     Minimal buffer length = (srclen - 8) bytes.
 *                     Input and output buffers can overlap if block function
 *                     supports that.
 *  @param[in]  src    Ciphertext as n 64-bit blocks.
 */
func (x *wrapDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%8 != 0 {
        panic("cryptobin/wrap: input not full blocks")
    }

    if len(dst) < len(src)-8 {
        panic("cryptobin/wrap: output smaller than input")
    }

    if len(src) == 0 {
        return
    }

    iv := x.iv
    inlen := len(src)

    empty := make([]byte, inlen-8)

    gotIv, err := x.cryptBlocks(dst, src)
    if err != nil {
        copy(dst, empty)
        return
    }

    if !bytes.Equal(gotIv, iv[:8]) {
        copy(dst, empty)
        return
    }

    copy(x.iv, iv)
}

func (x *wrapDecrypter) cryptBlocks(out, in []byte) (iv []byte, err error) {
    var A, R []byte
    var i, j, t int

    A = make([]byte, 16)

    inlen := len(in)

    inlen -= 8;
    if (((inlen & 0x7) != 0) || (inlen < 16) || (uint64(inlen) > WRAP_MAX)) {
        return nil, errors.New("invalid src")
    }

    t = 6 * (inlen >> 3)

    copy(A, in[:8])
    copy(out, in[8:])

    for j = 0; j < 6; j++ {
        for i = 0; i < inlen; i, t = i+8, t-1 {
            A[7] ^= byte(t & 0xff)
            if t > 0xff {
                A[6] ^= byte((t >> 8) & 0xff)
                A[5] ^= byte((t >> 16) & 0xff)
                A[4] ^= byte((t >> 24) & 0xff)
            }

            R = out[inlen - 8 - i:]

            copy(A[8:], R[:8])
            x.b.Decrypt(A, A)
            copy(R, A[8:])
        }
    }

    iv = make([]byte, 8)
    copy(iv, A[:8])

    return
}

func (x *wrapDecrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/wrap: incorrect length IV")
    }

    copy(x.iv, iv)
}
