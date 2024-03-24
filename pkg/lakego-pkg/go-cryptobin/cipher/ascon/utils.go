package ascon

import (
    "math/bits"
    "encoding/binary"
)

func pad(n int) uint64 {
    return 0x80 << (56 - 8*n)
}

func rotr(x uint64, n int) uint64 {
    return bits.RotateLeft64(x, -n)
}

func be64n(b []byte) uint64 {
    var x uint64
    for i := len(b) - 1; i >= 0; i-- {
        x |= uint64(b[i]) << (56 - i*8)
    }
    return x
}

func put64n(b []byte, x uint64) {
    for i := len(b) - 1; i >= 0; i-- {
        b[i] = byte(x >> (56 - 8*i))
    }
}

func mask(x uint64, n int) uint64 {
    for i := 0; i < n; i++ {
        x &^= 255 << (56 - 8*i)
    }
    return x
}

func additionalData128aGeneric(s *state, ad []byte) {
    for len(ad) >= BlockSize128a {
        s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
        s.x1 ^= binary.BigEndian.Uint64(ad[8:16])
        p8(s)
        ad = ad[BlockSize128a:]
    }
}

func encryptBlocks128aGeneric(s *state, dst, src []byte) {
    for len(src) >= BlockSize128a {
        s.x0 ^= binary.BigEndian.Uint64(src[0:8])
        s.x1 ^= binary.BigEndian.Uint64(src[8:16])
        binary.BigEndian.PutUint64(dst[0:8], s.x0)
        binary.BigEndian.PutUint64(dst[8:16], s.x1)
        p8(s)
        src = src[BlockSize128a:]
        dst = dst[BlockSize128a:]
    }
}

func decryptBlocks128aGeneric(s *state, dst, src []byte) {
    for len(src) >= BlockSize128a {
        c0 := binary.BigEndian.Uint64(src[0:8])
        c1 := binary.BigEndian.Uint64(src[8:16])
        binary.BigEndian.PutUint64(dst[0:8], s.x0^c0)
        binary.BigEndian.PutUint64(dst[8:16], s.x1^c1)
        s.x0 = c0
        s.x1 = c1
        p8(s)
        src = src[BlockSize128a:]
        dst = dst[BlockSize128a:]
    }
}

func roundGeneric(s *state, C uint64) {
    s0 := s.x0
    s1 := s.x1
    s2 := s.x2
    s3 := s.x3
    s4 := s.x4

    // Round constant
    s2 ^= C

    // Substitution
    s0 ^= s4
    s4 ^= s3
    s2 ^= s1

    // Keccak S-box
    t0 := s0 ^ (^s1 & s2)
    t1 := s1 ^ (^s2 & s3)
    t2 := s2 ^ (^s3 & s4)
    t3 := s3 ^ (^s4 & s0)
    t4 := s4 ^ (^s0 & s1)

    // Substitution
    t1 ^= t0
    t0 ^= t4
    t3 ^= t2
    t2 = ^t2

    // Linear diffusion
    //
    // x0 ← Σ0(x0) = x0 ⊕ (x0 ≫ 19) ⊕ (x0 ≫ 28)
    s.x0 = t0 ^ rotr(t0, 19) ^ rotr(t0, 28)
    // x1 ← Σ1(x1) = x1 ⊕ (x1 ≫ 61) ⊕ (x1 ≫ 39)
    s.x1 = t1 ^ rotr(t1, 61) ^ rotr(t1, 39)
    // x2 ← Σ2(x2) = x2 ⊕ (x2 ≫ 1) ⊕ (x2 ≫ 6)
    s.x2 = t2 ^ rotr(t2, 1) ^ rotr(t2, 6)
    // x3 ← Σ3(x3) = x3 ⊕ (x3 ≫ 10) ⊕ (x3 ≫ 17)
    s.x3 = t3 ^ rotr(t3, 10) ^ rotr(t3, 17)
    // x4 ← Σ4(x4) = x4 ⊕ (x4 ≫ 7) ⊕ (x4 ≫ 41)
    s.x4 = t4 ^ rotr(t4, 7) ^ rotr(t4, 41)
}

func p12Generic(s *state) {
    roundGeneric(s, 0xf0)
    roundGeneric(s, 0xe1)
    roundGeneric(s, 0xd2)
    roundGeneric(s, 0xc3)
    roundGeneric(s, 0xb4)
    roundGeneric(s, 0xa5)
    roundGeneric(s, 0x96)
    roundGeneric(s, 0x87)
    roundGeneric(s, 0x78)
    roundGeneric(s, 0x69)
    roundGeneric(s, 0x5a)
    roundGeneric(s, 0x4b)
}

func p8Generic(s *state) {
    roundGeneric(s, 0xb4)
    roundGeneric(s, 0xa5)
    roundGeneric(s, 0x96)
    roundGeneric(s, 0x87)
    roundGeneric(s, 0x78)
    roundGeneric(s, 0x69)
    roundGeneric(s, 0x5a)
    roundGeneric(s, 0x4b)
}

func p6Generic(s *state) {
    roundGeneric(s, 0x96)
    roundGeneric(s, 0x87)
    roundGeneric(s, 0x78)
    roundGeneric(s, 0x69)
    roundGeneric(s, 0x5a)
    roundGeneric(s, 0x4b)
}

func additionalData128a(s *state, ad []byte) {
    additionalData128aGeneric(s, ad)
}

func encryptBlocks128a(s *state, dst, src []byte) {
    encryptBlocks128aGeneric(s, dst, src)
}

func decryptBlocks128a(s *state, dst, src []byte) {
    decryptBlocks128aGeneric(s, dst, src)
}

func round(s *state, C uint64) {
    roundGeneric(s, C)
}

func p12(s *state) {
    p12Generic(s)
}

func p8(s *state) {
    p8Generic(s)
}

func p6(s *state) {
    p6Generic(s)
}
