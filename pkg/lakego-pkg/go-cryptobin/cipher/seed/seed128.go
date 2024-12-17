package seed

import (
    "fmt"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type seed128Cipher struct {
    pdwRoundKey [32]uint32
}

func newSeed128Cipher(key []byte) cipher.Block {
    c := new(seed128Cipher)
    c.expandKey(key)

    return c
}

func (s *seed128Cipher) BlockSize() int {
    return BlockSize
}

func (s *seed128Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/seed: invalid block size %d (src)", len(src)))
    }

    if len(dst) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/seed: invalid block size %d (dst)", len(dst)))
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/seed: invalid buffer overlap")
    }

    s.encrypt(dst, src)
}

func (s *seed128Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/seed: invalid block size %d (src)", len(src)))
    }

    if len(dst) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/seed: invalid block size %d (dst)", len(dst)))
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/seed: invalid buffer overlap")
    }

    s.decrypt(dst, src)
}

func (s *seed128Cipher) expandKey(key []byte) {
    A := binary.BigEndian.Uint32(key[0:])
    B := binary.BigEndian.Uint32(key[4:])
    C := binary.BigEndian.Uint32(key[8:])
    D := binary.BigEndian.Uint32(key[12:])

    var T0, T1 uint32
    for i := 0; i < 16; i++ {
        T0 = A + C - kc[i]
        T1 = B - D + kc[i]

        s.pdwRoundKey[i*2+0] = g(T0)
        s.pdwRoundKey[i*2+1] = g(T1)

        if (i % 2) == 0 {
            T0 = A
            A = (A >> 8) ^ (B << 24)
            B = (B >> 8) ^ (T0 << 24)
        } else {
            T0 = C
            C = (C << 8) ^ (D >> 24)
            D = (D << 8) ^ (T0 >> 24)
        }
    }
}

func (s *seed128Cipher) encrypt(dst, src []byte) {
    data := [...]uint32{
        binary.BigEndian.Uint32(src[0:]),
        binary.BigEndian.Uint32(src[4:]),
        binary.BigEndian.Uint32(src[8:]),
        binary.BigEndian.Uint32(src[12:]),
    }

    var t0, t1 uint32
    for i := 0; i < 32; i += 2 {
        if i%4 == 0 {
            t0 = data[2] ^ s.pdwRoundKey[i]
            t1 = data[3] ^ s.pdwRoundKey[i+1]

            t0, t1 = processBlock(t0, t1)

            data[0] ^= t0
            data[1] ^= t1
        } else {
            t0 = data[0] ^ s.pdwRoundKey[i]
            t1 = data[1] ^ s.pdwRoundKey[i+1]

            t0, t1 = processBlock(t0, t1)

            data[2] ^= t0
            data[3] ^= t1
        }
    }

    binary.BigEndian.PutUint32(dst[0:], data[2])
    binary.BigEndian.PutUint32(dst[4:], data[3])
    binary.BigEndian.PutUint32(dst[8:], data[0])
    binary.BigEndian.PutUint32(dst[12:], data[1])
}

func (s *seed128Cipher) decrypt(dst, src []byte) {
    data := [...]uint32{
        binary.BigEndian.Uint32(src[0:]),
        binary.BigEndian.Uint32(src[4:]),
        binary.BigEndian.Uint32(src[8:]),
        binary.BigEndian.Uint32(src[12:]),
    }

    var t0, t1 uint32
    for i := 30; i >= 0; i -= 2 {
        if i%4 == 0 {
            t0 = data[0] ^ s.pdwRoundKey[i]
            t1 = data[1] ^ s.pdwRoundKey[i+1]

            t0, t1 = processBlock(t0, t1)

            data[2] ^= t0
            data[3] ^= t1
        } else {
            t0 = data[2] ^ s.pdwRoundKey[i]
            t1 = data[3] ^ s.pdwRoundKey[i+1]

            t0, t1 = processBlock(t0, t1)

            data[0] ^= t0
            data[1] ^= t1
        }
    }

    binary.BigEndian.PutUint32(dst[0:], data[2])
    binary.BigEndian.PutUint32(dst[4:], data[3])
    binary.BigEndian.PutUint32(dst[8:], data[0])
    binary.BigEndian.PutUint32(dst[12:], data[1])
}
