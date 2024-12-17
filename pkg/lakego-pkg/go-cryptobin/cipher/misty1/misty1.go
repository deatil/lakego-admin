// Package misty1 implements the MISTY1 cipher
package misty1

import (
    "strconv"
    "crypto/cipher"
)

/*

https://en.wikipedia.org/wiki/MISTY1
http://tools.ietf.org/search/rfc2994

Note: This cipher should not be used: https://eprint.iacr.org/2015/746

*/

const (
    BlockSize = 8
    KeySize   = 16
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/misty1: invalid key size " + strconv.Itoa(int(k))
}

type misty1Cipher struct {
    ek [32]uint16
}

// New returns a cipher.Block implementing MISTY1.  The key argument must be 16 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
    if l := len(key); l != KeySize {
        return nil, KeySizeError(l)
    }

    c := &misty1Cipher{}
    c.expandKey(key)

    return c, nil
}

func (m *misty1Cipher) BlockSize() int {
    return BlockSize
}

func (m *misty1Cipher) Encrypt(dst, src []byte) {
    d0 := getUint32(src)
    d1 := getUint32(src[4:])

    // 0 round
    d0 = m.fl(d0, 0)
    d1 = m.fl(d1, 1)
    d1 = d1 ^ m.fo(d0, 0)

    // 1 round
    d0 = d0 ^ m.fo(d1, 1)
    // 2 round
    d0 = m.fl(d0, 2)
    d1 = m.fl(d1, 3)
    d1 = d1 ^ m.fo(d0, 2)
    // 3 round
    d0 = d0 ^ m.fo(d1, 3)

    // 4 round
    d0 = m.fl(d0, 4)
    d1 = m.fl(d1, 5)
    d1 = d1 ^ m.fo(d0, 4)
    // 5 round
    d0 = d0 ^ m.fo(d1, 5)
    // 6 round
    d0 = m.fl(d0, 6)
    d1 = m.fl(d1, 7)
    d1 = d1 ^ m.fo(d0, 6)
    // 7 round
    d0 = d0 ^ m.fo(d1, 7)
    // final
    d0 = m.fl(d0, 8)
    d1 = m.fl(d1, 9)

    putUint32(dst, d1)
    putUint32(dst[4:], d0)
}

func (m *misty1Cipher) Decrypt(dst, src []byte) {
    d1 := getUint32(src)
    d0 := getUint32(src[4:])

    d0 = m.flinv(d0, 8)
    d1 = m.flinv(d1, 9)
    d0 = d0 ^ m.fo(d1, 7)
    d1 = d1 ^ m.fo(d0, 6)
    d0 = m.flinv(d0, 6)
    d1 = m.flinv(d1, 7)
    d0 = d0 ^ m.fo(d1, 5)
    d1 = d1 ^ m.fo(d0, 4)
    d0 = m.flinv(d0, 4)
    d1 = m.flinv(d1, 5)

    d0 = d0 ^ m.fo(d1, 3)
    d1 = d1 ^ m.fo(d0, 2)
    d0 = m.flinv(d0, 2)
    d1 = m.flinv(d1, 3)
    d0 = d0 ^ m.fo(d1, 1)
    d1 = d1 ^ m.fo(d0, 0)
    d0 = m.flinv(d0, 0)
    d1 = m.flinv(d1, 1)

    putUint32(dst, d0)
    putUint32(dst[4:], d1)
}

func (m *misty1Cipher) expandKey(key []byte) {
    for i := 0; i < 8; i++ {
        m.ek[i] = uint16(key[i*2])*256 + uint16(key[i*2+1])
    }

    for i := 0; i < 8; i++ {
        m.ek[i+8] = fi(m.ek[i], m.ek[(i+1)%8])
        m.ek[i+16] = m.ek[i+8] & 0x1ff
        m.ek[i+24] = m.ek[i+8] >> 9
    }
}

func (m *misty1Cipher) fo(fin uint32, k int) uint32 {
    t0 := uint16(fin >> 16)
    t1 := uint16(fin & 0xffff)
    t0 = t0 ^ m.ek[k]
    t0 = fi(t0, m.ek[(k+5)%8+8])
    t0 = t0 ^ t1
    t1 = t1 ^ m.ek[(k+2)%8]
    t1 = fi(t1, m.ek[(k+1)%8+8])
    t1 = t1 ^ t0
    t0 = t0 ^ m.ek[(k+7)%8]
    t0 = fi(t0, m.ek[(k+3)%8+8])
    t0 = t0 ^ t1
    t1 = t1 ^ m.ek[(k+4)%8]
    fout := uint32(t1)<<16 | uint32(t0)
    return fout
}

func (m *misty1Cipher) fl(fin uint32, k int) uint32 {
    d0 := uint16(fin >> 16)
    d1 := uint16(fin & 0xffff)
    if k&1 == 0 {
        d1 = d1 ^ (d0 & m.ek[k/2])
        d0 = d0 ^ (d1 | m.ek[(k/2+6)%8+8])
    } else {
        d1 = d1 ^ (d0 & m.ek[((k-1)/2+2)%8+8])
        d0 = d0 ^ (d1 | m.ek[((k-1)/2+4)%8])
    }
    fout := uint32(d0)<<16 | uint32(d1)
    return fout
}

func (m *misty1Cipher) flinv(fin uint32, k int) uint32 {
    d0 := uint16(fin >> 16)
    d1 := uint16(fin & 0xffff)
    if k&1 == 0 {
        d0 = d0 ^ (d1 | m.ek[(k/2+6)%8+8])
        d1 = d1 ^ (d0 & m.ek[k/2])
    } else {
        d0 = d0 ^ (d1 | m.ek[((k-1)/2+4)%8])
        d1 = d1 ^ (d0 & m.ek[((k-1)/2+2)%8+8])
    }
    fout := uint32(d0)<<16 | uint32(d1)
    return fout
}
