package esch

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func GETU32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func PUTU32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
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

func tmin(a, b int) int {
    if a < b {
        return a
    }

    return b
}

func rotatel32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func rotater32(x uint32, n int) uint32 {
    return rotatel32(x, 32 - n)
}

func sparkle(H *[16]uint32, rounds int, ns int) {
    var s, i, j, px, py int
    var x, y uint32

    for s = 0; s < ns; s++ {
        H[1] ^= C[s % 8]
        H[3] ^= uint32(s)

        px = 0
        py = 1

        for j = 0; j < rounds; j++ {
            H[px] += rotater32(H[py], 31)
            H[py] ^= rotater32(H[px], 24)
            H[px] ^= C[j]
            H[px] += rotater32(H[py], 17)
            H[py] ^= rotater32(H[px], 17)
            H[px] ^= C[j]
            H[px] += H[py]
            H[py] ^= rotater32(H[px], 31)
            H[px] ^= C[j]
            H[px] += rotater32(H[py], 24)
            H[py] ^= rotater32(H[px], 16)
            H[px] ^= C[j]

            px += 2
            py += 2
        }

        x = H[0] ^ H[2] ^ H[4]
        y = H[1] ^ H[3] ^ H[5]
        if rounds > 6 {
            x ^= H[6]
            y ^= H[7]
        }

        x = rotater32(x ^ (x << 16), 16)
        y = rotater32(y ^ (y << 16), 16)

        j = rounds
        for i = 0; i < rounds; i += 2 {
            H[j] ^= H[i] ^ y
            H[j + 1] ^= H[i + 1] ^ x

            j += 2
        }

        x = H[rounds]
        y = H[rounds + 1]
        for i = 0; i < rounds - 2; i++ {
            H[i + rounds] = H[i]
            H[i] = H[i + rounds + 2]
        }

        H[rounds * 2 - 2] = H[rounds - 2]
        H[rounds * 2 - 1] = H[rounds - 1]
        H[rounds - 2] = x
        H[rounds - 1] = y
    }
}
