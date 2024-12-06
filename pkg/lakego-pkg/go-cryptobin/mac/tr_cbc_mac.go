package mac

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/padding"
)

type trCBCMAC struct {
    b    cipher.Block
    pad  padding.Padding
    size int
}

// NewTRCBCMAC returns a TR-CBC-MAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 7
//
// Reference: TrCBC: Another look at CBC-MAC.
func NewTRCBCMAC(b cipher.Block, size int) BlockCipherMAC {
    if size <= 0 || size > b.BlockSize() {
        panic("go-cryptobin/mac: invalid size")
    }

    return &trCBCMAC{
        b:    b,
        pad:  padding.NewISO97971(),
        size: size,
    }
}

func (t *trCBCMAC) Size() int {
    return t.size
}

func (t *trCBCMAC) MAC(src []byte) []byte {
    blockSize := t.b.BlockSize()
    tag := make([]byte, blockSize)

    padded := false
    if len(src) == 0 || len(src)%blockSize != 0 {
        src = t.pad.Padding(src, blockSize)
        padded = true
    }

    for len(src) > 0 {
        subtle.XORBytes(tag, tag, src[:blockSize])
        t.b.Encrypt(tag, tag)
        src = src[blockSize:]
    }

    if padded {
        return tag[blockSize-t.size:]
    }

    return tag[:t.size]
}
