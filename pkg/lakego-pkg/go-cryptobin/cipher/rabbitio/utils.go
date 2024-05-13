package rabbitio

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func getu16(ptr []byte) uint16 {
    if littleEndian {
        return binary.LittleEndian.Uint16(ptr)
    } else {
        return binary.BigEndian.Uint16(ptr)
    }
}

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

func rol32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func gfunction(u, v uint32) uint32 {
    uv := uint64(u + v)
    uv *= uv
    return uint32(uv>>32) ^ uint32(uv)
}
