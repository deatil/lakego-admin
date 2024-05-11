package fugue

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func getu32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func putu32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
    }
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint32(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint32(b[j:])
        }
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        if littleEndian {
            binary.LittleEndian.PutUint32(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint32(dst[j:], w[i])
        }
    }

    return dst
}

func rol(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func ror(x uint32, n int) uint32 {
    return rol(x, 32 - n)
}

func cmix30(S []uint32) {
    S[ 0] ^= S[4]
    S[ 1] ^= S[5]
    S[ 2] ^= S[6]
    S[15] ^= S[4]
    S[16] ^= S[5]
    S[17] ^= S[6]
}

func cmix36(S []uint32) {
    S[ 0] ^= S[4]
    S[ 1] ^= S[5]
    S[ 2] ^= S[6]
    S[18] ^= S[4]
    S[19] ^= S[5]
    S[20] ^= S[6]
}

func smix(S []uint32, i0, i1, i2, i3 int) {
    var c0 uint32 = 0
    var c1 uint32 = 0
    var c2 uint32 = 0
    var c3 uint32 = 0

    var r0 uint32 = 0
    var r1 uint32 = 0
    var r2 uint32 = 0
    var r3 uint32 = 0

    var tmp uint32
    var xt uint32

    xt = S[i0]
    tmp = mixtab0[byte(xt >> 24) & 0xFF]
    c0 ^= tmp
    tmp = mixtab1[byte(xt >> 16) & 0xFF]
    c0 ^= tmp
    r1 ^= tmp
    tmp = mixtab2[byte(xt >>  8) & 0xFF]
    c0 ^= tmp
    r2 ^= tmp
    tmp = mixtab3[byte(xt >>  0) & 0xFF]
    c0 ^= tmp
    r3 ^= tmp
    xt = S[i1]
    tmp = mixtab0[byte(xt >> 24) & 0xFF]
    c1 ^= tmp
    r0 ^= tmp
    tmp = mixtab1[byte(xt >> 16) & 0xFF]
    c1 ^= tmp
    tmp = mixtab2[byte(xt >>  8) & 0xFF]
    c1 ^= tmp
    r2 ^= tmp
    tmp = mixtab3[byte(xt >>  0) & 0xFF]
    c1 ^= tmp
    r3 ^= tmp
    xt = S[i2]
    tmp = mixtab0[byte(xt >> 24) & 0xFF]
    c2 ^= tmp
    r0 ^= tmp
    tmp = mixtab1[byte(xt >> 16) & 0xFF]
    c2 ^= tmp
    r1 ^= tmp
    tmp = mixtab2[byte(xt >>  8) & 0xFF]
    c2 ^= tmp
    tmp = mixtab3[byte(xt >>  0) & 0xFF]
    c2 ^= tmp
    r3 ^= tmp
    xt = S[i3]
    tmp = mixtab0[byte(xt >> 24) & 0xFF]
    c3 ^= tmp
    r0 ^= tmp
    tmp = mixtab1[byte(xt >> 16) & 0xFF]
    c3 ^= tmp
    r1 ^= tmp
    tmp = mixtab2[byte(xt >>  8) & 0xFF]
    c3 ^= tmp
    r2 ^= tmp
    tmp = mixtab3[byte(xt >>  0) & 0xFF]
    c3 ^= tmp
    S[i0] = ((c0 ^ (r0 <<  0)) & 0xFF000000) |
            ((c1 ^ (r1 <<  0)) & 0x00FF0000) |
            ((c2 ^ (r2 <<  0)) & 0x0000FF00) |
            ((c3 ^ (r3 <<  0)) & 0x000000FF)
    S[i1] = ((c1 ^ (r0 <<  8)) & 0xFF000000) |
            ((c2 ^ (r1 <<  8)) & 0x00FF0000) |
            ((c3 ^ (r2 <<  8)) & 0x0000FF00) |
            ((c0 ^ (r3 >> 24)) & 0x000000FF)
    S[i2] = ((c2 ^ (r0 << 16)) & 0xFF000000) |
            ((c3 ^ (r1 << 16)) & 0x00FF0000) |
            ((c0 ^ (r2 >> 16)) & 0x0000FF00) |
            ((c1 ^ (r3 >> 16)) & 0x000000FF)
    S[i3] = ((c3 ^ (r0 << 24)) & 0xFF000000) |
            ((c0 ^ (r1 >>  8)) & 0x00FF0000) |
            ((c1 ^ (r2 >>  8)) & 0x0000FF00) |
            ((c2 ^ (r3 >>  8)) & 0x000000FF)
}
