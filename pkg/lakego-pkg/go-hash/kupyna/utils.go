package kupyna

import (
    "encoding/binary"
)

func GETU64(ptr []byte) uint64 {
    return binary.LittleEndian.Uint64(ptr)
}

func PUTU64(ptr []byte, a uint64) {
    binary.LittleEndian.PutUint64(ptr, a)
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
