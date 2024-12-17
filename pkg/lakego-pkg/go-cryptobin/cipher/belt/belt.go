package belt

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// BELT block cipher, defined in STB 34.101.31

const BlockSize = 16

// KeySizeError is returned when key size in bytes
// isn't one of 16, 24, or 32.
type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/belt: invalid key size %d", int(k))
}

type beltCipher struct {
    ks [32]byte
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(beltCipher)
    c.expandKey(key)

    return c, nil
}

func (c *beltCipher) BlockSize() int {
    return BlockSize
}

func (c *beltCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/belt: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/belt: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/belt: invalid buffer overlap")
    }

    c.encrypt(dst, src)
}

func (c *beltCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/belt: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/belt: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/belt: invalid buffer overlap")
    }

    c.decrypt(dst, src)
}

func (cc *beltCipher) encrypt(out, in []byte) {
    var a, b, c, d, e uint32
    var i uint32

    a = getu32(in[0:])
    b = getu32(in[4:])
    c = getu32(in[8:])
    d = getu32(in[12:])

    ks := cc.ks

    var key uint32

    for i = 0; i < 8; i++ {
        key = getu32(ks[4*KIdx[i][0]:])
        b ^= G(a + key, 5)

        key = getu32(ks[4*KIdx[i][1]:])
        c ^= G(d + key, 21)

        key = getu32(ks[4*KIdx[i][2]:])
        a = (a - G(b + key, 13))

        key = getu32(ks[4*KIdx[i][3]:])
        e = G(b + c + key, 21) ^ (i + 1)

        b += e
        c = uint32(c - e)

        key = getu32(ks[4*KIdx[i][4]:])
        d += G(c + key, 13)

        key = getu32(ks[4*KIdx[i][5]:])
        b ^= G(a + key, 21)

        key = getu32(ks[4*KIdx[i][6]:])
        c ^= G(d + key, 5)

        a, b = b, a
        c, d = d, c
        b, c = c, b
    }

    putu32(out[0:], b)
    putu32(out[4:], d)
    putu32(out[8:], a)
    putu32(out[12:], c)
}

func (cc *beltCipher) decrypt(out, in []byte) {
    var a, b, c, d, e uint32
    var i uint32

    a = getu32(in[0:])
    b = getu32(in[4:])
    c = getu32(in[8:])
    d = getu32(in[12:])

    ks := cc.ks

    for i = 0; i < 8; i++ {
        var key uint32

        j := 7 - i

        key = getu32(ks[4*KIdx[j][6]:])
        b ^= G(a + key, 5)

        key = getu32(ks[4*KIdx[j][5]:])
        c ^= G(d + key, 21)

        key = getu32(ks[4*KIdx[j][4]:])
        a = uint32(a - G(b + key, 13))

        key = getu32(ks[4*KIdx[j][3]:])
        e = G(b + c + key, 21) ^ (j + 1)

        b += e
        c = uint32(c - e)

        key = getu32(ks[4*KIdx[j][2]:])
        d += G(c + key, 13)

        key = getu32(ks[4*KIdx[j][1]:])
        b ^= G(a + key, 21)

        key = getu32(ks[4*KIdx[j][0]:])
        c ^= G(d + key, 5)

        a, b = b, a
        c, d = d, c
        a, d = d, a
    }

    putu32(out[0:], c)
    putu32(out[4:], a)
    putu32(out[8:], d)
    putu32(out[12:], b)
}

func (c *beltCipher) expandKey(k []byte) {
    var i int

    kLen := len(k)

    switch (kLen) {
        case 16:
            for i = 0; i < 16; i++ {
                c.ks[i]      = k[i]
                c.ks[i + 16] = k[i]
            }

        case 24:
            for i = 0; i < 24; i++ {
                c.ks[i] = k[i]
            }

            for i = 24; i < 32; i++ {
                c.ks[i] = k[i - 24] ^ k[i - 20] ^ k[i - 16]
            }

        case 32:
            for i = 0; i < 32; i++ {
                c.ks[i] = k[i]
            }
    }
}
