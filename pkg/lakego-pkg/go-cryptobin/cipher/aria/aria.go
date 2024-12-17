package aria

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

// KeySizeError is returned when key size in bytes
// isn't one of 16, 24, or 32.
type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/aria: invalid key size %d", int(k))
}

type ariaCipher struct {
    k   int // Key size in bytes.
    enc []uint32
    dec []uint32
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the ARIA key,
// either 16, 24, or 32 bytes to select
// ARIA-128, ARIA-192, or ARIA-256.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(ariaCipher)
    c.expandKey(key)

    return c, nil
}

func (c *ariaCipher) BlockSize() int {
    return BlockSize
}

func (c *ariaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/aria: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/aria: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/aria: invalid buffer overlap")
    }

    c.cryptBlock(dst, src, c.enc)
}

func (c *ariaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/aria: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/aria: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/aria: invalid buffer overlap")
    }

    c.cryptBlock(dst, src, c.dec)
}

func (c *ariaCipher) rounds() int {
    return c.k/4 + 8
}

func (c *ariaCipher) cryptBlock(dst, src []byte, xk []uint32) {
    n := c.rounds()

    var p [16]byte

    copy(p[:], src[:BlockSize])

    for i := 1; i <= n-1; i++ {
        if i&1 == 1 {
            p = roundOdd(p, toBytes(xk[(i-1)*4:i*4]))
        } else {
            p = roundEven(p, toBytes(xk[(i-1)*4:i*4]))
        }
    }

    p = xor(substitute2(xor(p, toBytes(xk[(n-1)*4:n*4]))), toBytes(xk[n*4:(n+1)*4]))

    copy(dst[:BlockSize], p[:])
}

func (c *ariaCipher) expandKey(key []byte) {
    k := len(key)
    n := k + 36

    c.k = k
    c.enc = make([]uint32, n)
    c.dec = make([]uint32, n)

    c.keyRound(key)
}

func (c *ariaCipher) keyRound(key []byte) {
    n := c.rounds()

    var kl, kr [16]byte

    for i := 0; i < c.k; i++ {
        if i < 16 {
            kl[i] = key[i]
        } else {
            kr[i-16] = key[i]
        }
    }

    var ck1, ck2, ck3 [16]byte

    switch c.k {
        case 128 / 8:
            ck1 = c1
            ck2 = c2
            ck3 = c3
        case 192 / 8:
            ck1 = c2
            ck2 = c3
            ck3 = c1
        case 256 / 8:
            ck1 = c3
            ck2 = c1
            ck3 = c2
    }

    var w0, w1, w2, w3 [16]byte

    w0 = kl
    w1 = xor(roundOdd(w0, ck1), kr)
    w2 = xor(roundEven(w1, ck2), w0)
    w3 = xor(roundOdd(w2, ck3), w1)

    copyBytes(c.enc, xor(w0, rrot(w1, 19)))
    copyBytes(c.enc[4:], xor(w1, rrot(w2, 19)))
    copyBytes(c.enc[8:], xor(w2, rrot(w3, 19)))
    copyBytes(c.enc[12:], xor(w3, rrot(w0, 19)))
    copyBytes(c.enc[16:], xor(w0, rrot(w1, 31)))
    copyBytes(c.enc[20:], xor(w1, rrot(w2, 31)))
    copyBytes(c.enc[24:], xor(w2, rrot(w3, 31)))
    copyBytes(c.enc[28:], xor(w3, rrot(w0, 31)))
    copyBytes(c.enc[32:], xor(w0, lrot(w1, 61)))
    copyBytes(c.enc[36:], xor(w1, lrot(w2, 61)))
    copyBytes(c.enc[40:], xor(w2, lrot(w3, 61)))
    copyBytes(c.enc[44:], xor(w3, lrot(w0, 61)))
    copyBytes(c.enc[48:], xor(w0, lrot(w1, 31)))

    if n > 12 {
        copyBytes(c.enc[52:], xor(w1, lrot(w2, 31)))
        copyBytes(c.enc[56:], xor(w2, lrot(w3, 31)))
    }

    if n > 14 {
        copyBytes(c.enc[60:], xor(w3, lrot(w0, 31)))
        copyBytes(c.enc[64:], xor(w0, lrot(w1, 19)))
    }

    copy(c.dec, c.enc[n*4:(n+1)*4])

    for i := 1; i <= n-1; i++ {
        var t [16]byte

        t = toBytes(c.enc[(n-i)*4 : (n-i+1)*4])
        t = diffuse(t)

        copyBytes(c.dec[i*4:], t)
    }

    copy(c.dec[n*4:], c.enc[:4])
}
