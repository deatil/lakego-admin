package bmw

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

func circularLeft32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func circularLeft64(x uint64, n int) uint64 {
    return bits.RotateLeft64(x, n)
}
