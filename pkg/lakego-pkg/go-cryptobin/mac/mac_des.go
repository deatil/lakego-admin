package mac

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/padding"
)

type macDES struct {
    b1, b2, b3 cipher.Block
    pad        padding.Padding
    size       int
}

// NewMACDES returns a MAC-DES instance that implements MAC with the given block cipher.
// The padding scheme is ISO/IEC 9797-1 method 2.
// GB/T 15821.1-2020 MAC scheme 4
func NewMACDES(creator BlockCipherFunc, key1, key2 []byte, size int) BlockCipherMAC {
    var b1, b2, b3 cipher.Block
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

    key3 := make([]byte, len(key2))
    copy(key3, key2)

    for i := 0; i < len(key3); i++ {
        key3[i] ^= 0xF0
    }

    if b3, err = creator(key3); err != nil {
        panic(err)
    }

    return &macDES{
        b1:   b1,
        b2:   b2,
        b3:   b3,
        pad:  padding.NewISO97971(),
        size: size,
    }
}

func (m *macDES) Size() int {
    return m.size
}

func (m *macDES) MAC(src []byte) []byte {
    blockSize := m.b1.BlockSize()
    src = m.pad.Padding(src, blockSize)

    tag := make([]byte, blockSize)
    copy(tag, src[:blockSize])

    m.b1.Encrypt(tag, tag)
    m.b3.Encrypt(tag, tag)

    src = src[blockSize:]
    for len(src) > 0 {
        subtle.XORBytes(tag, tag, src[:blockSize])
        m.b1.Encrypt(tag, tag)
        src = src[blockSize:]
    }

    m.b2.Encrypt(tag, tag)

    return tag[:m.size]
}
