package kuznyechik

import (
    "fmt"
    "crypto/cipher"
    "encoding/binary"
)

const BlockSize = 16

func NewCipher(key []byte) (cipher.Block, error) {
    if len(key) != 32 {
        return nil, fmt.Errorf("cryptobin/kuznyechik: invalid key size %d", len(key))
    }

    k00 := binary.LittleEndian.Uint64(key[0:8])
    k01 := binary.LittleEndian.Uint64(key[8:16])
    k10 := binary.LittleEndian.Uint64(key[16:24])
    k11 := binary.LittleEndian.Uint64(key[24:32])
    k := new(kuznyechikCipher)
    k.erk[0][0] = k00
    k.erk[0][1] = k01
    k.erk[1][0] = k10
    k.erk[1][1] = k11
    k00, k01, k10, k11 = fk(k00, k01, k10, k11, 0)
    k.erk[2][0] = k00
    k.erk[2][1] = k01
    k.erk[3][0] = k10
    k.erk[3][1] = k11
    k00, k01, k10, k11 = fk(k00, k01, k10, k11, 8)
    k.erk[4][0] = k00
    k.erk[4][1] = k01
    k.erk[5][0] = k10
    k.erk[5][1] = k11
    k00, k01, k10, k11 = fk(k00, k01, k10, k11, 16)
    k.erk[6][0] = k00
    k.erk[6][1] = k01
    k.erk[7][0] = k10
    k.erk[7][1] = k11
    k00, k01, k10, k11 = fk(k00, k01, k10, k11, 24)
    k.erk[8][0] = k00
    k.erk[8][1] = k01
    k.erk[9][0] = k10
    k.erk[9][1] = k11
    // drf is based on erk
    k.drk[0] = k.erk[0] // first element is just copied
    for i := 1; i < 10; i++ {
        k.drk[i][0], k.drk[i][1] = ilss(k.erk[i][0], k.erk[i][1])
    }
    return k, nil
}

func (k *kuznyechikCipher) BlockSize() int {
    return BlockSize
}

func (k *kuznyechikCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/kuznyechik: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/kuznyechik: output not full block")
    }
    
    x1 := binary.LittleEndian.Uint64(src[0:8])
    x2 := binary.LittleEndian.Uint64(src[8:16])
    var t1, t2 uint64
    x1 ^= k.erk[0][0]
    x2 ^= k.erk[0][1]
    t1, t2 = ls(x1, x2)
    t1 ^= k.erk[1][0]
    t2 ^= k.erk[1][1]
    x1, x2 = ls(t1, t2)
    x1 ^= k.erk[2][0]
    x2 ^= k.erk[2][1]
    t1, t2 = ls(x1, x2)
    t1 ^= k.erk[3][0]
    t2 ^= k.erk[3][1]
    x1, x2 = ls(t1, t2)
    x1 ^= k.erk[4][0]
    x2 ^= k.erk[4][1]
    t1, t2 = ls(x1, x2)
    t1 ^= k.erk[5][0]
    t2 ^= k.erk[5][1]
    x1, x2 = ls(t1, t2)
    x1 ^= k.erk[6][0]
    x2 ^= k.erk[6][1]
    t1, t2 = ls(x1, x2)
    t1 ^= k.erk[7][0]
    t2 ^= k.erk[7][1]
    x1, x2 = ls(t1, t2)
    x1 ^= k.erk[8][0]
    x2 ^= k.erk[8][1]
    t1, t2 = ls(x1, x2)
    t1 ^= k.erk[9][0]
    t2 ^= k.erk[9][1]
    binary.LittleEndian.PutUint64(dst[0:8], t1)
    binary.LittleEndian.PutUint64(dst[8:16], t2)
}

func (k *kuznyechikCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/kuznyechik: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/kuznyechik: output not full block")
    }
    
    x1 := binary.LittleEndian.Uint64(src[0:8])
    x2 := binary.LittleEndian.Uint64(src[8:16])
    var t1, t2 uint64
    t1, t2 = ilss(x1, x2)
    t1 ^= k.drk[9][0]
    t2 ^= k.drk[9][1]
    x1, x2 = ils(t1, t2)
    x1 ^= k.drk[8][0]
    x2 ^= k.drk[8][1]
    t1, t2 = ils(x1, x2)
    t1 ^= k.drk[7][0]
    t2 ^= k.drk[7][1]
    x1, x2 = ils(t1, t2)
    x1 ^= k.drk[6][0]
    x2 ^= k.drk[6][1]
    t1, t2 = ils(x1, x2)
    t1 ^= k.drk[5][0]
    t2 ^= k.drk[5][1]
    x1, x2 = ils(t1, t2)
    x1 ^= k.drk[4][0]
    x2 ^= k.drk[4][1]
    t1, t2 = ils(x1, x2)
    t1 ^= k.drk[3][0]
    t2 ^= k.drk[3][1]
    x1, x2 = ils(t1, t2)
    x1 ^= k.drk[2][0]
    x2 ^= k.drk[2][1]
    t1, t2 = ils(x1, x2)
    t1 ^= k.drk[1][0]
    t2 ^= k.drk[1][1]
    t1 = isi(t1)
    t2 = isi(t2)
    t1 ^= k.drk[0][0]
    t2 ^= k.drk[0][1]
    binary.LittleEndian.PutUint64(dst[0:8], t1)
    binary.LittleEndian.PutUint64(dst[8:16], t2)
}
