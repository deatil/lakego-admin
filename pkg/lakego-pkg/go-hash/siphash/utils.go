package siphash

import (
    "math/bits"
    "encoding/binary"
)

func ROTL(x, n uint64) uint64 {
    return bits.RotateLeft64(x, int(n))
}

// Endianness option
const littleEndian bool = true

func GETU64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func PUTU64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
    }
}

func sipround(v0, v1, v2, v3 *uint64) {
    (*v0) += (*v1)
    (*v1) = ROTL((*v1), 13)

    (*v1) ^= (*v0)
    (*v0) = ROTL((*v0), 32)

    (*v2) += (*v3)
    (*v3) = ROTL((*v3), 16)

    (*v3) ^= (*v2)
    (*v0) += (*v3)
    (*v3) = ROTL((*v3), 21)

    (*v3) ^= (*v0)
    (*v2) += (*v1)
    (*v1) = ROTL((*v1), 17)

    (*v1) ^= (*v2)
    (*v2) = ROTL((*v2), 32)
}
