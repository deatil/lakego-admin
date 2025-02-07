package haval

import (
    "math/bits"
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
}

func getu64(ptr []byte) uint64 {
    return binary.LittleEndian.Uint64(ptr)
}

func putu64(ptr []byte, a uint64) {
    binary.LittleEndian.PutUint64(ptr, a)
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.LittleEndian.Uint32(b[j:])
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        binary.LittleEndian.PutUint32(dst[j:], w[i])
    }

    return dst
}

func circularLeft(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func circularRight(x uint32, n int) uint32 {
    return circularLeft(x, 32 - n)
}

func F1(x6, x5, x4, x3, x2, x1, x0 uint32) uint32 {
    return (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0
}

func F2(x6, x5, x4, x3, x2, x1, x0 uint32) uint32 {
    return (x2 & ((x1 & ^x3) ^ (x4 & x5) ^ x6 ^ x0)) ^
        (x4 & (x1 ^ x5)) ^ ((x3 & x5) ^ x0)
}

func F3(x6, x5, x4, x3, x2, x1, x0 uint32) uint32 {
    return (x3 & ((x1 & x2) ^ x6 ^ x0)) ^
        (x1 & x4) ^ (x2 & x5) ^ x0
}

func F4(x6, x5, x4, x3, x2, x1, x0 uint32) uint32 {
    return (x3 & ((x1 & x2) ^ (x4 | x6) ^ x5)) ^
        (x4 & ((^x2 & x5) ^ x1 ^ x6 ^ x0)) ^ (x2 & x6) ^ x0
}

func F5(x6, x5, x4, x3, x2, x1, x0 uint32) uint32 {
    return (x0 & ^((x1 & x2 & x3) ^ x5)) ^
        (x1 & x4) ^ (x2 & x5) ^ (x3 & x6)
}

func mix128(a0, a1, a2, a3 uint32, n int) uint32 {
    tmp := (a0 & 0x000000FF) |
           (a1 & 0x0000FF00) |
           (a2 & 0x00FF0000) |
           (a3 & 0xFF000000)
    if n > 0 {
        tmp = circularLeft(tmp, n)
    }

    return tmp
}

func mix160_0(x5, x6, x7 uint32) uint32 {
    return circularLeft(
        (x5 & 0x01F80000) |
        (x6 & 0xFE000000) |
        (x7 & 0x0000003F),
        13,
    )
}

func mix160_1(x5, x6, x7 uint32) uint32 {
    return circularLeft(
        (x5 & 0xFE000000) |
        (x6 & 0x0000003F) |
        (x7 & 0x00000FC0),
        7,
    )
}

func mix160_2(x5, x6, x7 uint32) uint32 {
    return (x5 & 0x0000003F) |
        (x6 & 0x00000FC0) |
        (x7 & 0x0007F000)
}

func mix160_3(x5, x6, x7 uint32) uint32 {
    return ((x5 & 0x00000FC0) |
        (x6 & 0x0007F000) |
        (x7 & 0x01F80000)) >> 6
}

func mix160_4(x5, x6, x7 uint32) uint32 {
    return ((x5 & 0x0007F000) |
        (x6 & 0x01F80000) |
        (x7 & 0xFE000000)) >> 12
}

func mix192_0(x6, x7 uint32) uint32 {
    return circularLeft((x6 & 0xFC000000) | (x7 & 0x0000001F), 6)
}

func mix192_1(x6, x7 uint32) uint32 {
    return (x6 & 0x0000001F) | (x7 & 0x000003E0)
}

func mix192_2(x6, x7 uint32) uint32 {
    return ((x6 & 0x000003E0) | (x7 & 0x0000FC00)) >> 5
}

func mix192_3(x6, x7 uint32) uint32 {
    return ((x6 & 0x0000FC00) | (x7 & 0x001F0000)) >> 10
}

func mix192_4(x6, x7 uint32) uint32 {
    return ((x6 & 0x001F0000) | (x7 & 0x03E00000)) >> 16
}

func mix192_5(x6, x7 uint32) uint32 {
    return ((x6 & 0x03E00000) | (x7 & 0xFC000000)) >> 21
}
