package gost

import "strconv"

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/gost: invalid key size: " + strconv.Itoa(int(k))
}

type SboxSizeError int

func (k SboxSizeError) Error() string {
    return "cryptobin/gost: invalid sbox size: " + strconv.Itoa(int(k))
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
        uint32(kbox[3][x & 255])

    return (x << 11) | (x >> (32 - 11))
}

// Endianness option
const littleEndian bool = false

// Convert a byte slice to a uint32 slice
func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        if littleEndian {
            dst[i] =
                uint32(b[j+0]) << 24 |
                uint32(b[j+1]) << 16 |
                uint32(b[j+2]) <<  8 |
                uint32(b[j+3])
        } else {
            dst[i] =
                uint32(b[j+0])       |
                uint32(b[j+1]) <<  8 |
                uint32(b[j+2]) << 16 |
                uint32(b[j+3]) << 24
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
            dst[j+0] = byte(w[i] >> 24)
            dst[j+1] = byte(w[i] >> 16)
            dst[j+2] = byte(w[i] >> 8)
            dst[j+3] = byte(w[i])
        } else {
            dst[j+0] = byte(w[i])
            dst[j+1] = byte(w[i] >> 8)
            dst[j+2] = byte(w[i] >> 16)
            dst[j+3] = byte(w[i] >> 24)
        }
    }

    return dst
}
