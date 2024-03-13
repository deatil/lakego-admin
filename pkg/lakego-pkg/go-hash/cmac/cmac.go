package cmac

import (
    "hash"
    "errors"
    "crypto/cipher"
    "crypto/subtle"
)

// Package cmac implements the fast CMAC MAC based on
// a block cipher. This mode of operation fixes security
// deficiencies of CBC-MAC (CBC-MAC is secure only for
// fixed-length messages). CMAC is equal to OMAC1.
// This implementations supports block ciphers with a
// block size of:
//  -   64 bit
//  -  128 bit
//  -  256 bit
//  -  512 bit
//  - 1024 bit
// Common ciphers like AES, Serpent etc. operate on 128 bit
// blocks. 256, 512 and 1024 are supported for the Threefish
// tweakable block cipher. Ciphers with 64 bit blocks are
// supported, but not recommened.
// CMAC (with AES) is specified in RFC 4493 and RFC 4494.

const (
    // minimal irreducible polynomial for blocksize
    p64   = 0x1b    // for 64  bit block ciphers
    p128  = 0x87    // for 128 bit block ciphers (like AES)
    p256  = 0x425   // special for large block ciphers (Threefish)
    p512  = 0x125   // special for large block ciphers (Threefish)
    p1024 = 0x80043 // special for large block ciphers (Threefish)
)

var (
    errUnsupportedCipher = errors.New("cipher block size not supported")
    errInvalidTagSize    = errors.New("tags size must between 1 and the cipher's block size")
)

// Sum computes the CMAC checksum with the given tagsize of msg using the cipher.Block.
func Sum(msg []byte, c cipher.Block, tagsize int) ([]byte, error) {
    h, err := NewWithTagSize(c, tagsize)
    if err != nil {
        return nil, err
    }

    h.Write(msg)
    return h.Sum(nil), nil
}

// Verify computes the CMAC checksum with the given tagsize of msg and compares
// it with the given mac. This functions returns true if and only if the given mac
// is equal to the computed one.
func Verify(mac, msg []byte, c cipher.Block, tagsize int) bool {
    sum, err := Sum(msg, c, tagsize)
    if err != nil {
        return false
    }

    return subtle.ConstantTimeCompare(mac, sum) == 1
}

// New returns a hash.Hash computing the CMAC checksum.
func New(c cipher.Block) (hash.Hash, error) {
    return NewWithTagSize(c, c.BlockSize())
}

// NewWithTagSize returns a hash.Hash computing the CMAC checksum with the
// given tag size. The tag size must between the 1 and the cipher's block size.
func NewWithTagSize(c cipher.Block, tagsize int) (hash.Hash, error) {
    blocksize := c.BlockSize()

    if tagsize <= 0 || tagsize > blocksize {
        return nil, errInvalidTagSize
    }

    var p int
    switch blocksize {
        default:
            return nil, errUnsupportedCipher
        case 8:
            p = p64
        case 16:
            p = p128
        case 32:
            p = p256
        case 64:
            p = p512
        case 128:
            p = p1024
    }

    m := &macFunc{
        cipher: c,
        k0:     make([]byte, blocksize),
        k1:     make([]byte, blocksize),
        buf:    make([]byte, blocksize),
    }
    m.tagsize = tagsize
    c.Encrypt(m.k0, m.k0)

    v := shift(m.k0, m.k0)
    m.k0[blocksize-1] ^= byte(subtle.ConstantTimeSelect(v, p, 0))

    v = shift(m.k1, m.k0)
    m.k1[blocksize-1] ^= byte(subtle.ConstantTimeSelect(v, p, 0))

    return m, nil
}

// The CMAC message auth. function
type macFunc struct {
    cipher  cipher.Block
    k0, k1  []byte
    buf     []byte
    off     int
    tagsize int
}

func (h *macFunc) Size() int {
    return h.cipher.BlockSize()
}

func (h *macFunc) BlockSize() int {
    return h.cipher.BlockSize()
}

func (h *macFunc) Reset() {
    for i := range h.buf {
        h.buf[i] = 0
    }
    h.off = 0
}

func (h *macFunc) Write(msg []byte) (int, error) {
    bs := h.BlockSize()
    n := len(msg)

    if h.off > 0 {
        dif := bs - h.off
        if n > dif {
            xor(h.buf[h.off:], msg[:dif])

            msg = msg[dif:]
            h.cipher.Encrypt(h.buf, h.buf)
            h.off = 0
        } else {
            xor(h.buf[h.off:], msg)

            h.off += n
            return n, nil
        }
    }

    if length := len(msg); length > bs {
        nn := length & (^(bs - 1))
        if length == nn {
            nn -= bs
        }
        for i := 0; i < nn; i += bs {
            xor(h.buf, msg[i:i+bs])

            h.cipher.Encrypt(h.buf, h.buf)
        }
        msg = msg[nn:]
    }

    if length := len(msg); length > 0 {
        xor(h.buf[h.off:], msg)

        h.off += length
    }

    return n, nil
}

func (h *macFunc) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d := *h
    hash := d.checkSum()
    return append(in, hash...)
}

func (h *macFunc) checkSum() []byte {
    blocksize := h.cipher.BlockSize()

    // Don't change the buffer so the
    // caller can keep writing and suming.
    hash := make([]byte, blocksize)

    if h.off < blocksize {
        copy(hash, h.k1)
    } else {
        copy(hash, h.k0)
    }

    xor(hash, h.buf)
    if h.off < blocksize {
        hash[h.off] ^= 0x80
    }

    h.cipher.Encrypt(hash, hash)

    return hash[:h.tagsize]
}

func shift(dst, src []byte) int {
    var b, bit byte
    for i := len(src) - 1; i >= 0; i-- { // a range would be nice
        bit = src[i] >> 7
        dst[i] = src[i]<<1 | b
        b = bit
    }

    return int(b)
}

// XOR the contents of b into a in-place
func xor(a, b []byte) {
    subtle.XORBytes(a, a, b)
}
