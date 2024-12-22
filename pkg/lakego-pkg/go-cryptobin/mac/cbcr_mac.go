package mac

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/padding"
)

type cbcrMAC struct {
    b    cipher.Block
    pad  padding.Padding
    size int
}

// NewCBCRMAC returns a CBCRMAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 8
//
// Reference: CBCR: CBC MAC with rotating transformations.
func NewCBCRMAC(b cipher.Block, size int) BlockCipherMAC {
    if size <= 0 || size > b.BlockSize() {
        panic("go-cryptobin/mac: invalid size")
    }

    return &cbcrMAC{
        b:    b,
        pad:  padding.NewISO97971(),
        size: size,
    }
}

func (c *cbcrMAC) Size() int {
    return c.size
}

func (c *cbcrMAC) MAC(src []byte) []byte {
    blockSize := c.b.BlockSize()
    tag := make([]byte, blockSize)

    c.b.Encrypt(tag, tag)

    padded := false
    if len(src) == 0 || len(src)%blockSize != 0 {
        src = c.pad.Padding(src, blockSize)
        padded = true
    }

    for len(src) > blockSize {
        subtle.XORBytes(tag, tag, src[:blockSize])
        c.b.Encrypt(tag, tag)

        src = src[blockSize:]
    }

    subtle.XORBytes(tag, tag, src[:blockSize])

    if padded {
        shiftLeft(tag)
    } else {
        shiftRight(tag)
    }

    c.b.Encrypt(tag, tag)

    return tag[:c.size]
}

func shiftRight(x []byte) {
    var lsb byte
    for i := 0; i < len(x); i++ {
        lsb, x[i] = x[i]<<7, x[i]>>1|lsb
    }

    x[0] ^= lsb
}
