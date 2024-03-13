package ascon

import (
    "math/bits"
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
