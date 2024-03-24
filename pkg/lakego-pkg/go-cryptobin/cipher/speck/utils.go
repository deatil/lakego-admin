package speck

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func keyToUint64s(b []byte) []uint64 {
    size := len(b) / 8
    dst := make([]uint64, size)

    for i := 0; i < size; i++ {
        j := i * 8

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint64(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint64(b[j:])
        }
    }

    return dst
}

func uint64sToBytes(w []uint64) []byte {
    size := len(w) * 8
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 8

        if littleEndian {
            binary.LittleEndian.PutUint64(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint64(dst[j:], w[i])
        }
    }

    return dst
}

func rotatel64(x uint64, n int) uint64 {
    return bits.RotateLeft64(x, n)
}

func rotater64(x uint64, n int) uint64 {
    return rotatel64(x, 64 - n)
}

func ks(x uint64, y *uint64, pk uint64, nk *uint64, i uint64) {
    (*y) = (pk + rotater64(x, 8)) ^ i
    (*nk) = rotatel64(pk, 3) ^ (*y)
}
