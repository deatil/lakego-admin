// Package spritz implements the Spritz stream-cipher
package spritz

import (
    "strconv"
    "crypto/cipher"
)

/*

http://people.csail.mit.edu/rivest/pubs/RS14.pdf

This is an unoptimized implementation using the algorithms straight from the
PDF.  This cipher is new and has not been sufficiently analysed.  You probably
shouldn't use this for anything.

*/

const BlockSize = 1

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/spritz: invalid key size " + strconv.Itoa(int(k))
}

const N = 256

type spritzCipher struct {
    i, j, k byte
    z, a, w byte
    s       [N]byte
    iv      []byte
}

// New returns a cipher.Block implementing RC6.
func NewCipher(key []byte) (cipher.Block, error) {
    l := len(key)
    if l == 0 {
        return nil, KeySizeError(l)
    }

    c := &spritzCipher{}
    c.keySetup(key)

    return c, nil
}

func NewCipherWithIV(key, iv []byte) (cipher.Block, error) {
    l := len(key)
    if l == 0 {
        return nil, KeySizeError(l)
    }

    c := &spritzCipher{}
    c.keySetup(key)
    c.iv = iv

    return c, nil
}

func (c *spritzCipher) BlockSize() int {
    return BlockSize
}

func (c *spritzCipher) Encrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/spritz: output not full block")
    }

    if c.iv != nil {
        ct := c.encryptWithIV(src)
        copy(dst, ct)
    } else {
        ct := c.encrypt(src)
        copy(dst, ct)
    }
}

func (c *spritzCipher) Decrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/spritz: output not full block")
    }

    if c.iv != nil {
        ct := c.decryptWithIV(src)
        copy(dst, ct)
    } else {
        ct := c.decrypt(src)
        copy(dst, ct)
    }
}

func (c *spritzCipher) encrypt(m []byte) []byte {
    ctxt := make([]byte, len(m))

    for i, x := range c.squeeze(len(ctxt)) {
        ctxt[i] = m[i] + x
    }

    return ctxt
}

func (c *spritzCipher) decrypt(m []byte) []byte {
    ptxt := make([]byte, len(m))

    for i, x := range c.squeeze(len(ptxt)) {
        ptxt[i] = m[i] - x
    }

    return ptxt
}

func (c *spritzCipher) encryptWithIV(m []byte) []byte {
    c.absorbStop()
    c.absorb(c.iv)

    ctxt := make([]byte, len(m))

    for i, x := range c.squeeze(len(ctxt)) {
        ctxt[i] = m[i] + x
    }

    return ctxt
}

func (c *spritzCipher) decryptWithIV(m []byte) []byte {
    c.absorbStop()
    c.absorb(c.iv)

    ptxt := make([]byte, len(m))

    for i, x := range c.squeeze(len(ptxt)) {
        ptxt[i] = m[i] - x
    }

    return ptxt
}

func (c *spritzCipher) initializeState() {
    c.w = 1

    for i := 0; i < N; i++ {
        c.s[i] = byte(i)
    }
}

func (c *spritzCipher) absorb(I []byte) {
    for _, b := range I {
        c.absorbByte(b)
    }
}

func (c *spritzCipher) absorbByte(b byte) {
    c.absorbNibble(b & 0x0f)
    c.absorbNibble((b & 0xf0) >> 4)
}

func (c *spritzCipher) absorbNibble(x byte) {

    if c.a == N/2 {
        c.shuffle()
    }

    c.s[c.a], c.s[N/2+x] = c.s[N/2+x], c.s[c.a]
    c.a++
}

func (c *spritzCipher) absorbStop() {

    if c.a == N/2 {
        c.shuffle()
    }

    c.a++
}

func (c *spritzCipher) shuffle() {
    c.whip(2 * N)
    c.crush()
    c.whip(2 * N)
    c.crush()
    c.whip(2 * N)
    c.a = 0
}

func (c *spritzCipher) whip(r int) {
    for v := 0; v < r; v++ {
        c.update()
    }

    c.w += 2
}

func (c *spritzCipher) crush() {

    for v := 0; v < N/2; v++ {
        if c.s[v] > c.s[N-1-v] {
            c.s[v], c.s[N-1-v] = c.s[N-1-v], c.s[v]
        }
    }
}

func (c *spritzCipher) squeeze(r int) []byte {

    if c.a > 0 {
        c.shuffle()
    }

    p := make([]byte, r)

    for v := 0; v < r; v++ {
        p[v] = c.drip()
    }

    return p
}

func (c *spritzCipher) drip() byte {
    if c.a > 0 {
        c.shuffle()
    }

    c.update()

    return c.output()
}

func (c *spritzCipher) update() {
    c.i = c.i + c.w
    c.j = c.k + c.s[c.j+c.s[c.i]]
    c.k = c.i + c.k + c.s[c.j]
    c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
}

func (c *spritzCipher) output() byte {
    c.z = c.s[c.j+c.s[c.i+c.s[c.z+c.k]]]
    return c.z
}

func (c *spritzCipher) keySetup(k []byte) {
    c.initializeState()
    c.absorb(k)
}
