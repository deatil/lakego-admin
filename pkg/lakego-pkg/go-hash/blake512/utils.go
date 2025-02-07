package blake512

import (
    "math/bits"
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
}

func getu64(ptr []byte) uint64 {
    return binary.BigEndian.Uint64(ptr)
}

func putu64(ptr []byte, a uint64) {
    binary.BigEndian.PutUint64(ptr, a)
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.BigEndian.Uint32(b[j:])
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        binary.BigEndian.PutUint32(dst[j:], w[i])
    }

    return dst
}

func bytesToUint64s(b []byte) []uint64 {
    size := len(b) / 8
    dst := make([]uint64, size)

    for i := 0; i < size; i++ {
        j := i * 8

        dst[i] = binary.BigEndian.Uint64(b[j:])
    }

    return dst
}

func circularRight(x uint64, n int) uint64 {
    return bits.RotateLeft64(x, 64 - n)
}
