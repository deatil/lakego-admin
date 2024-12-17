package kuznyechik

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// GOST 34.12-2015 128-bit Kuznechik block cipher.

const BlockSize = 16

type kuznyechikCipher struct {
    // erk is used in Encrypt, drk is used in Decrypt.
    erk, drk [10][2]uint64
}

func NewCipher(key []byte) (cipher.Block, error) {
    if len(key) != 32 {
        return nil, fmt.Errorf("go-cryptobin/kuznyechik: invalid key size %d", len(key))
    }

    k := new(kuznyechikCipher)
    k.expandKey(key)

    return k, nil
}

func (k *kuznyechikCipher) BlockSize() int {
    return BlockSize
}

func (k *kuznyechikCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/kuznyechik: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/kuznyechik: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/kuznyechik: invalid buffer overlap")
    }

    k.encrypt(dst, src)
}

func (k *kuznyechikCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/kuznyechik: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/kuznyechik: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/kuznyechik: invalid buffer overlap")
    }

    k.decrypt(dst, src)
}

func (k *kuznyechikCipher) encrypt(dst, src []byte) {
    x1 := getu64(src[0:8])
    x2 := getu64(src[8:16])

    var t1, t2 uint64

    x1 ^= k.erk[0][0]
    x2 ^= k.erk[0][1]
    t1, t2 = ls(x1, x2)
    t1 ^= k.erk[1][0]
    t2 ^= k.erk[1][1]

    for i := 2; i < 10; i += 2 {
        x1, x2 = ls(t1, t2)
        x1 ^= k.erk[i][0]
        x2 ^= k.erk[i][1]

        t1, t2 = ls(x1, x2)
        t1 ^= k.erk[i+1][0]
        t2 ^= k.erk[i+1][1]
    }

    putu64(dst[0:], t1)
    putu64(dst[8:], t2)
}

func (k *kuznyechikCipher) decrypt(dst, src []byte) {
    x1 := getu64(src[0:])
    x2 := getu64(src[8:])

    var t1, t2 uint64

    t1, t2 = ilss(x1, x2)
    t1 ^= k.drk[9][0]
    t2 ^= k.drk[9][1]

    for i := 8; i > 0; i -= 2 {
        x1, x2 = ils(t1, t2)
        x1 ^= k.drk[i][0]
        x2 ^= k.drk[i][1]

        t1, t2 = ils(x1, x2)
        t1 ^= k.drk[i-1][0]
        t2 ^= k.drk[i-1][1]
    }

    t1 = isi(t1)
    t2 = isi(t2)
    t1 ^= k.drk[0][0]
    t2 ^= k.drk[0][1]

    putu64(dst[0:], t1)
    putu64(dst[8:], t2)
}

func (k *kuznyechikCipher) expandKey(key []byte) {
    k00 := getu64(key[0:])
    k01 := getu64(key[8:])
    k10 := getu64(key[16:])
    k11 := getu64(key[24:])

    k.erk[0][0] = k00
    k.erk[0][1] = k01
    k.erk[1][0] = k10
    k.erk[1][1] = k11

    for i := 2; i < 10; i += 2 {
        k00, k01, k10, k11 = fk(k00, k01, k10, k11, 4*i-8)
        k.erk[i][0] = k00
        k.erk[i][1] = k01
        k.erk[i+1][0] = k10
        k.erk[i+1][1] = k11
    }

    // drf is based on erk
    k.drk[0] = k.erk[0] // first element is just copied
    for i := 1; i < 10; i++ {
        k.drk[i][0], k.drk[i][1] = ilss(k.erk[i][0], k.erk[i][1])
    }
}
