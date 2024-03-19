package gost

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

// Convert a byte slice to a uint32 slice
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

// Convert a uint32 slice to a byte slice
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

func rotl32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

// Expand s-box
func sboxExpansion(s [][]byte) [][]byte {
    // allocate buffer
    k := make([][]byte, 4)
    for i := 0; i < len(k); i++ {
        k[i] = make([]byte, 256)
    }

    // compute expansion
    for i := 0; i < 256; i++ {
        k[0][i] = (s[7][i>>4] << 4) | s[6][i&15]
        k[1][i] = (s[5][i>>4] << 4) | s[4][i&15]
        k[2][i] = (s[3][i>>4] << 4) | s[2][i&15]
        k[3][i] = (s[1][i>>4] << 4) | s[0][i&15]
    }

    return k
}

// Compute GOST cycle
func cycle(x uint32, kbox [][]byte) uint32 {
    x = uint32(kbox[0][(x >> 24) & 255]) << 24 |
        uint32(kbox[1][(x >> 16) & 255]) << 16 |
        uint32(kbox[2][(x >>  8) & 255]) <<  8 |
        uint32(kbox[3][ x        & 255])

    // rotate result left by 11 bits
    return rotl32(x, 11)
}
