package mac

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/padding"
)

// cbcmac implements the basic CBC-MAC mode of operation for block ciphers.
type cbcmac struct {
    b    cipher.Block
    pad  padding.Padding
    size int
}

// NewCBCMAC returns a CBC-MAC instance that implements the MAC with the given block cipher.
// The padding scheme is ISO/IEC 9797-1 method 2.
// GB/T 15821.1-2020 MAC scheme 1
func NewCBCMAC(b cipher.Block, size int) BlockCipherMAC {
    if size <= 0 || size > b.BlockSize() {
        panic("go-cryptobin/mac: invalid size")
    }

    return &cbcmac{
        b:    b,
        pad:  padding.NewISO97971(),
        size: size,
    }
}

func (c *cbcmac) Size() int {
    return c.size
}

// MAC calculates the MAC of the given data.
// The data is padded with the padding scheme of the block cipher before processing.
func (c *cbcmac) MAC(src []byte) []byte {
    blockSize := c.b.BlockSize()
    src = c.pad.Padding(src, blockSize)

    tag := make([]byte, blockSize)
    for len(src) > 0 {
        subtle.XORBytes(tag, tag, src[:blockSize])
        c.b.Encrypt(tag, tag)
        src = src[blockSize:]
    }

    return tag[:c.size]
}
