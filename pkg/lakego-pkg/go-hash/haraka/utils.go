package haraka

import (
    "encoding/binary"
)

func GETU32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func PUTU32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
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
