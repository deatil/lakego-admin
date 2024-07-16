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

// The CMAC message auth. function
type cmac struct {
    cipher  cipher.Block
    k0, k1  []byte
    buf     []byte
    off     int
    tagsize int
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

    m := &cmac{
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

func (d *cmac) Size() int {
    return d.tagsize
}

func (d *cmac) BlockSize() int {
    return d.cipher.BlockSize()
}

func (d *cmac) Reset() {
    for i := range d.buf {
        d.buf[i] = 0
    }
    d.off = 0
}

func (d *cmac) Write(msg []byte) (int, error) {
    bs := d.BlockSize()
    n := len(msg)

    if d.off > 0 {
        dif := bs - d.off
        if n > dif {
            xor(d.buf[d.off:], msg[:dif])

            msg = msg[dif:]
            d.cipher.Encrypt(d.buf, d.buf)
            d.off = 0
        } else {
            xor(d.buf[d.off:], msg)

            d.off += n
            return n, nil
        }
    }

    if length := len(msg); length > bs {
        nn := length & (^(bs - 1))
        if length == nn {
            nn -= bs
        }
        for i := 0; i < nn; i += bs {
            xor(d.buf, msg[i:i+bs])

            d.cipher.Encrypt(d.buf, d.buf)
        }
        msg = msg[nn:]
    }

    if length := len(msg); length > 0 {
        xor(d.buf[d.off:], msg)

        d.off += length
    }

    return n, nil
}

func (d *cmac) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *cmac) checkSum() []byte {
    blocksize := d.cipher.BlockSize()

    // Don't change the buffer so the
    // caller can keep writing and suming.
    hash := make([]byte, blocksize)

    if d.off < blocksize {
        copy(hash, d.k1)
    } else {
        copy(hash, d.k0)
    }

    xor(hash, d.buf)
    if d.off < blocksize {
        hash[d.off] ^= 0x80
    }

    d.cipher.Encrypt(hash, hash)

    return hash[:d.tagsize]
}
