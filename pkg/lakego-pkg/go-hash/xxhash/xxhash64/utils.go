package xxhash64

import (
    "math/bits"
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func getu64(ptr []byte) uint64 {
    return binary.LittleEndian.Uint64(ptr)
}

func putu64(ptr []byte, a uint64) {
    binary.LittleEndian.PutUint64(ptr, a)
}

func putu64be(ptr []byte, a uint64) {
    binary.BigEndian.PutUint64(ptr, a)
}

func bytesToUint64s(b []byte) []uint64 {
    size := len(b) / 8
    dst := make([]uint64, size)

    for i := 0; i < size; i++ {
        j := i * 8

        dst[i] = binary.LittleEndian.Uint64(b[j:])
    }

    return dst
}

func uint64sToBytes(w []uint64) []byte {
    size := len(w) * 8
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 8

        binary.LittleEndian.PutUint64(dst[j:], w[i])
    }

    return dst
}

func rotl(x, n uint64) uint64 {
    return bits.RotateLeft64(x, int(n))
}

func round(acc, input uint64) uint64 {
    acc += input * prime[1]
    acc  = rotl(acc, 31)
    acc *= prime[0]
    return acc
}

func mergeRound(acc, val uint64) uint64 {
    val  = round(0, val)
    acc ^= val
    acc  = acc * prime[0] + prime[3]
    return acc
}

func avalanche(h64 uint64) uint64 {
    h64 ^= h64 >> 33
    h64 *= prime[1]
    h64 ^= h64 >> 29
    h64 *= prime[2]
    h64 ^= h64 >> 32
    return h64
}
