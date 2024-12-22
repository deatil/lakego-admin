package mac

import (
    "crypto/subtle"
    "crypto/cipher"
)

type cmac struct {
    b      cipher.Block
    k1, k2 []byte
    size   int
}

// NewCMAC returns a CMAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 5
//
// Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf
func NewCMAC(b cipher.Block, size int) BlockCipherMAC {
    if size <= 0 || size > b.BlockSize() {
        panic("go-cryptobin/mac: invalid size")
    }

    blockSize := b.BlockSize()

    k1 := make([]byte, blockSize)
    k2 := make([]byte, blockSize)

    b.Encrypt(k1, k1)

    msb := shiftLeft(k1)
    k1[len(k1)-1] ^= msb * 0b10000111

    copy(k2, k1)
    msb = shiftLeft(k2)
    k2[len(k2)-1] ^= msb * 0b10000111

    return &cmac{
        b: b,
        k1: k1,
        k2: k2,
        size: size,
    }
}

func (c *cmac) Size() int {
    return c.size
}

func (c *cmac) MAC(src []byte) []byte {
    blockSize := c.b.BlockSize()

    tag := make([]byte, blockSize)
    if len(src) == 0 {
        // Special-cased as a single empty partial final block.
        copy(tag, c.k2)
        tag[len(src)] ^= 0b10000000

        c.b.Encrypt(tag, tag)
        return tag
    }

    for len(src) >= blockSize {
        subtle.XORBytes(tag, src[:blockSize], tag)
        if len(src) == blockSize {
            // Final complete block.
            subtle.XORBytes(tag, c.k1, tag)
        }

        c.b.Encrypt(tag, tag)

        src = src[blockSize:]
    }

    if len(src) > 0 {
        // Final incomplete block.
        subtle.XORBytes(tag, src, tag)
        subtle.XORBytes(tag, c.k2, tag)
        tag[len(src)] ^= 0b10000000

        c.b.Encrypt(tag, tag)
    }

    return tag[:c.size]
}

// shiftLeft sets x to x << 1, and returns MSB₁(x).
func shiftLeft(x []byte) byte {
    var msb byte
    for i := len(x) - 1; i >= 0; i-- {
        msb, x[i] = x[i]>>7, x[i]<<1|msb
    }

    return msb
}
