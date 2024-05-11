package hamsi

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

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

func getu64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func putu64(ptr []byte, a uint64) {
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

func ror(x uint32, n int) uint32 {
    return rol(x, 32 - n)
}
