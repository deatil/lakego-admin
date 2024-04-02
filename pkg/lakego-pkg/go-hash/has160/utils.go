package has160

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func GETU32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func PUTU32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
    }
}

func PUTU64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
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

func f1(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += rol(h[a], s1[j]) + x[x1[j]] + 0x00000000 + ((h[b] & h[c]) | ((^h[b]) & h[d]))
    h[b] = rol(h[b], 10)
}

func f2(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += rol(h[a], s1[j]) + x[x2[j]] + 0x5a827999 + (h[b] ^ h[c] ^ h[d])
    h[b] = rol(h[b], 17)
}

func f3(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += rol(h[a], s1[j]) + x[x3[j]] + 0x6ed9eba1 + (h[c] ^ (h[b] | (^h[d])))
    h[b] = rol(h[b], 25)
}

func f4(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += rol(h[a], s1[j]) + x[x4[j]] + 0x8f1bbcdc + (h[b] ^ h[c] ^ h[d])
    h[b] = rol(h[b], 30)
}
