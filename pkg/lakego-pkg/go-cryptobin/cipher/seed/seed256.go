package seed

import (
    "fmt"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type seed256Cipher struct {
    pdwRoundKey [48]uint32
}

var (
    seed256rot = [...]int{12, 9, 9, 11, 11, 12}
)

func newSeed256Cipher(key []byte) cipher.Block {
    c := new(seed256Cipher)
    c.expandKey(key)

    return c
}

func (s *seed256Cipher) BlockSize() int {
    return BlockSize
}

func (s *seed256Cipher) Encrypt(dst, src []byte) {
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

func (s *seed256Cipher) Decrypt(dst, src []byte) {
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

func (s *seed256Cipher) encrypt(dst, src []byte) {
    data := [...]uint32{
        binary.BigEndian.Uint32(src[0:]),
        binary.BigEndian.Uint32(src[4:]),
        binary.BigEndian.Uint32(src[8:]),
        binary.BigEndian.Uint32(src[12:]),
    }

    var t0, t1 uint32
    for i := 0; i < 48; i += 2 {
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

func (s *seed256Cipher) decrypt(dst, src []byte) {
    data := [...]uint32{
        binary.BigEndian.Uint32(src[0:]),
        binary.BigEndian.Uint32(src[4:]),
        binary.BigEndian.Uint32(src[8:]),
        binary.BigEndian.Uint32(src[12:]),
    }

    var t0, t1 uint32
    for i := 46; i >= 0; i -= 2 {
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

func (s *seed256Cipher) expandKey(key []byte) {
    A := binary.BigEndian.Uint32(key[0:])
    B := binary.BigEndian.Uint32(key[4:])
    C := binary.BigEndian.Uint32(key[8:])
    D := binary.BigEndian.Uint32(key[12:])
    E := binary.BigEndian.Uint32(key[16:])
    F := binary.BigEndian.Uint32(key[20:])
    G := binary.BigEndian.Uint32(key[24:])
    H := binary.BigEndian.Uint32(key[28:])

    var T0, T1 uint32
    var rot int

    T0 = (((A + C) ^ E) - F) ^ kc[0]
    T1 = (((B - D) ^ G) + H) ^ kc[0]
    s.pdwRoundKey[0] = g(T0)
    s.pdwRoundKey[1] = g(T1)

    for i := 1; i < 24; i++ {
        rot = seed256rot[i%6]

        if ((i + 1) % 2) == 0 {
            T0 = D
            D = (D >> rot) ^ (C << (32 - rot))
            C = (C >> rot) ^ (B << (32 - rot))
            B = (B >> rot) ^ (A << (32 - rot))
            A = (A >> rot) ^ (T0 << (32 - rot))
        } else {
            T0 = E
            E = (E << rot) ^ (F >> (32 - rot))
            F = (F << rot) ^ (G >> (32 - rot))
            G = (G << rot) ^ (H >> (32 - rot))
            H = (H << rot) ^ (T0 >> (32 - rot))
        }

        T0 = (((A + C) ^ E) - F) ^ kc[i]
        T1 = (((B - D) ^ G) + H) ^ kc[i]

        s.pdwRoundKey[i*2+0] = g(T0)
        s.pdwRoundKey[i*2+1] = g(T1)
    }
}
