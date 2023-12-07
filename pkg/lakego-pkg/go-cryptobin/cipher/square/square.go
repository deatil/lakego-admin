package square

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("cryptobin/square: invalid key size %d", int(k))
}

const BlockSize = 32

type squareCipher struct {
    key []uint16
}

// NewCipher creates and returns a new cipher.Stream.
func NewCipher(key []byte) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(squareCipher)
    c.key = bytesToUint16s(key)

    return c, nil
}

func (this *squareCipher) BlockSize() int {
    return BlockSize
}

func (this *squareCipher) XORKeyStream(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/square: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/square: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/square: invalid buffer overlap")
    }

    var rcon uint16
    var rk [16]uint16
    var i int32

    var a [16]uint16
    aUint16s := bytesToUint16s(src)
    copy(a[0:], aUint16s)

    rcon = 1
    for i = 0; i < 16; i++ {
        rk[i] = this.key[i]
    }

    theta(rk)
    sigma(a, rk)

    for i = 0; i < 16; i++ {
        rk[i] = this.key[i]
    }

    gamma(a)
    pi(a)
    keysched(rk, &rcon)
    sigma(a, rk)

    for i = 2; i <= R; i++ {
        theta(a)
        gamma(a)
        pi(a)
        keysched(rk, &rcon)
        sigma(a, rk)
    }

    dstBytes := uint16sToBytes(a[:])
    copy(dst, dstBytes)
}
