package mac

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/padding"
)

type ansiRetailMAC struct {
    b1, b2 cipher.Block
    pad    padding.Padding
    size   int
}

// NewANSIRetailMAC returns an ANSI Retail MAC instance that implements MAC with the given block cipher.
// The padding scheme is ISO/IEC 9797-1 method 2.
// GB/T 15821.1-2020 MAC scheme 3
func NewANSIRetailMAC(creator BlockCipherFunc, key1, key2 []byte, size int) BlockCipherMAC {
    var b1, b2 cipher.Block
    var err error

    if b1, err = creator(key1); err != nil {
        panic(err)
    }

    if size <= 0 || size > b1.BlockSize() {
        panic("go-cryptobin/mac: invalid size")
    }

    if b2, err = creator(key2); err != nil {
        panic(err)
    }

    return &ansiRetailMAC{
        b1:   b1,
        b2:   b2,
        pad:  padding.NewISO97971(),
        size: size,
    }
}

func (e *ansiRetailMAC) Size() int {
    return e.size
}

func (e *ansiRetailMAC) MAC(src []byte) []byte {
    blockSize := e.b1.BlockSize()
    src = e.pad.Padding(src, blockSize)

    tag := make([]byte, blockSize)
    for len(src) > 0 {
        subtle.XORBytes(tag, tag, src[:blockSize])
        e.b1.Encrypt(tag, tag)
        src = src[blockSize:]
    }

    e.b2.Decrypt(tag, tag)
    e.b1.Encrypt(tag, tag)

    return tag[:e.size]
}
