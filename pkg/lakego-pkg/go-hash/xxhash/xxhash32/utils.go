package xxhash32

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

func putu32be(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
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

func rotl(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func round(acc, input uint32) uint32 {
    acc += input * prime[1]
    acc  = rotl(acc, 13)
    acc *= prime[0]

    return acc
}

func avalanche(h32 uint32) uint32 {
    h32 ^= h32 >> 15
    h32 *= prime[1]
    h32 ^= h32 >> 13
    h32 *= prime[2]
    h32 ^= h32 >> 16

    return h32
}
