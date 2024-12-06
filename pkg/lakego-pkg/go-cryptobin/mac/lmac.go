package mac

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/padding"
)

type lmac struct {
    b1, b2 cipher.Block
    pad    padding.Padding
    size   int
}

// NewLMAC returns an LMAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 6
func NewLMAC(creator BlockCipherFunc, key []byte, size int) BlockCipherMAC {
    var b, b1, b2 cipher.Block
    var err error

    if b, err = creator(key); err != nil {
        panic(err)
    }

    if size <= 0 || size > b.BlockSize() {
        panic("go-cryptobin/mac: invalid size")
    }

    blockSize := b.BlockSize()

    key1 := make([]byte, blockSize)
    key1[blockSize-1] = 0x01

    key2 := make([]byte, blockSize)
    key2[blockSize-1] = 0x02

    b.Encrypt(key1, key1)
    b.Encrypt(key2, key2)

    if b1, err = creator(key1); err != nil {
        panic(err)
    }

    if b2, err = creator(key2); err != nil {
        panic(err)
    }

    return &lmac{
        b1:   b1,
        b2:   b2,
        pad:  padding.NewISO97971(),
        size: size,
    }
}

func (l *lmac) Size() int {
    return l.b1.BlockSize()
}

func (l *lmac) MAC(src []byte) []byte {
    blockSize := l.b1.BlockSize()
    src = l.pad.Padding(src, blockSize)

    tag := make([]byte, blockSize)
    for len(src) > blockSize {
        subtle.XORBytes(tag, tag, src[:blockSize])
        l.b1.Encrypt(tag, tag)
        src = src[blockSize:]
    }

    subtle.XORBytes(tag, tag, src[:blockSize])

    l.b2.Encrypt(tag, tag)

    return tag
}
