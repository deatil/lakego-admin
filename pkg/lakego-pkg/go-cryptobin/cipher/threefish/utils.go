package threefish

import (
    "math/bits"
    "encoding/binary"
)

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

func bytesToUint64s(b []byte) []uint64 {
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

func rotl64(x uint64, n int) uint64 {
    return bits.RotateLeft64(x, n)
}

func rotr64(x uint64, n int) uint64 {
    return rotl64(x, 64 - n)
}

// calculateTweak loads a tweak value from src and extends it into dst.
func calculateTweak(dst *[(tweakSize / 8) + 1]uint64, src []byte) error {
    if len(src) != tweakSize {
        return new(TweakSizeError)
    }

    dst[0] = GETU64(src[0:])
    dst[1] = GETU64(src[8:])
    dst[2] = dst[0] ^ dst[1]

    return nil
}
