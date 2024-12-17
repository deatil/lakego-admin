package rc5

import (
    "crypto/cipher"
)

const (
    W16         = 16      // word size in bits
    WW16        = W16 / 8 // word size in bytes
    B16         = 32      // block size in bits
    BB16        = B16 / 8 // block size in bytes

    // BlockSize the RC5/16 block size in bytes.
    BlockSize16 = BB16

    P16         = 0xb7e1
    Q16         = 0x9e37
)

type cipher16 struct {
    K []byte   // secret key
    b uint     // byte length of secret key
    R uint     // number of rounds
    S []uint16 // expanded key table
    T uint     // number of words in expanded key table
}

func newCipher16(key []byte, rounds uint) (cipher.Block, error) {
    // key length in range [0, 2040] bits -> [0, 255] bytes
    if n := len(key); n > 255 {
        return nil, KeySizeError(n)
    }

    S, T := newKeyTable16(rounds)
    L, LL := bytesToWords16(key)
    S, T = expandKeyTable16(S, T, L, LL)

    c := cipher16{
        key,
        uint(len(key) / 8),
        rounds,
        S,
        T,
    }

    return &c, nil
}

func (c *cipher16) BlockSize() int {
    return BlockSize16
}

func (c *cipher16) Encrypt(dst, src []byte) {
    if len(src) < BlockSize16 {
        panic("go-cryptobin/rc5-16: input not full block")
    }

    if len(dst) < BlockSize16 {
        panic("go-cryptobin/rc5-16: output not full block")
    }

    if inexactOverlap(dst[:BlockSize16], src[:BlockSize16]) {
        panic("go-cryptobin/rc5-16: invalid buffer overlap")
    }

    A, B := get16(src)
    A, B = A + c.S[0], B + c.S[1]

    for i := uint(1); i <= c.R; i++ {
        A = rotl16(A^B, B&15) + c.S[2 * i]
        B = rotl16(B^A, A&15) + c.S[2 * i + 1]
    }

    put16(dst, A, B)
}

func (c *cipher16) Decrypt(dst, src []byte) {
    if len(src) < BlockSize16 {
        panic("go-cryptobin/rc5-16: input not full block")
    }

    if len(dst) < BlockSize16 {
        panic("go-cryptobin/rc5-16: output not full block")
    }

    if inexactOverlap(dst[:BlockSize16], src[:BlockSize16]) {
        panic("go-cryptobin/rc5-16: invalid buffer overlap")
    }

    A, B := get16(src)

    for i := int(c.R); i >= 1; i-- {
        B = rotr16(B - c.S[2 *i + 1], A&15) ^ A
        A = rotr16(A - c.S[2 * i], B&15) ^ B
    }

    B = B - c.S[1]
    A = A - c.S[0]

    put16(dst, A, B)
}

func newKeyTable16(R uint) ([]uint16, uint) {
    T := 2 * (R + 1)
    S := make([]uint16, T)

    S[0] = P16
    for i := uint(1); i < T; i++  {
        S[i] = S[i-1] + Q16
    }

    return S, T
}

func bytesToWords16(key []byte) ([]uint16, uint) {
    LL := uint(len(key) / WW16)
    L := make([]uint16, LL)

    for i := uint(0); i < LL; i++ {
        L[i] = getUint16(key[:WW16])
        key = key[WW16:]
    }

    return L, LL
}

func expandKeyTable16(S []uint16, T uint, L []uint16, LL uint) ([]uint16, uint) {
    k := 3 * T
    if (LL > T) {
        k = 3 * LL
    }

    A, B := uint16(0), uint16(0)
    i, j := uint(0), uint(0)

    for ; k > 0; k-- {
        A = rotl16(S[i] + A + B, 3)
        S[i] = A
        B = rotl16(L[j] + A + B, (A + B)&15)
        L[j] = B
        i = (i + 1) % T
        j = (j + 1) % LL
    }

    return S, T
}

func getUint16(b []byte) uint16 {
    return uint16(b[0]) | uint16(b[1]) <<  8
}

func get16(b []byte) (uint16, uint16) {
    return uint16(b[0]) | uint16(b[1]) <<  8, uint16(b[2]) | uint16(b[3]) << 8
}

func put16(dst[] byte, a uint16, b uint16) {
    dst[0] = byte(a)
    dst[1] = byte(a >> 8)
    dst[2] = byte(b)
    dst[3] = byte(b >> 8)
}

func putUint16(k uint16) []byte {
    b := make([]byte, 2)
    b[0] = byte(k)
    b[1] = byte(k >> 8)
    return b
}

func rotl16(k uint16, r uint16) uint16 {
    return (k << r) | (k >> (16 - r))
}

func rotr16(k uint16, r uint16) uint16 {
    return (k >> r) | (k << (16 - r))
}
