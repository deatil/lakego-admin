package chaskey

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

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

func timestwo(out []uint32, in []uint32) {
    var C = [2]uint32{0x00, 0x87}
    out[0] = (in[0] << 1) ^ C[in[3]>>31]
    out[1] = (in[1] << 1) | (in[0] >> 31)
    out[2] = (in[2] << 1) | (in[1] >> 31)
    out[3] = (in[3] << 1) | (in[2] >> 31)
}

func block(dig *digest, m []byte) {
    v0, v1, v2, v3 := dig.s[0], dig.s[1], dig.s[2], dig.s[3]

    v0 ^= binary.LittleEndian.Uint32(m[0:])
    v1 ^= binary.LittleEndian.Uint32(m[4:])
    v2 ^= binary.LittleEndian.Uint32(m[8:])
    v3 ^= binary.LittleEndian.Uint32(m[12:])

    // permute
    for i := 0; i < dig.r; i++ {
        // round
        v0 += v1
        v2 += v3
        v1 = bits.RotateLeft32(v1, 5)
        v3 = bits.RotateLeft32(v3, 8)
        v1 ^= v0
        v3 ^= v2
        v0 = bits.RotateLeft32(v0, 16)
        v0 += v3
        v2 += v1
        v3 = bits.RotateLeft32(v3, 13)
        v1 = bits.RotateLeft32(v1, 7)
        v3 ^= v0
        v1 ^= v2
        v2 = bits.RotateLeft32(v2, 16)
    }

    dig.s[0], dig.s[1], dig.s[2], dig.s[3] = v0, v1, v2, v3
}

func lastblock(dig *digest) {
    v0, v1, v2, v3 := dig.s[0], dig.s[1], dig.s[2], dig.s[3]

    m := dig.x

    var l [4]uint32
    var lastblock [4]uint32

    if dig.nx == 16 {
        l = dig.k1

        lastblock[0] = binary.LittleEndian.Uint32(m[0:])
        lastblock[1] = binary.LittleEndian.Uint32(m[4:])
        lastblock[2] = binary.LittleEndian.Uint32(m[8:])
        lastblock[3] = binary.LittleEndian.Uint32(m[12:])

    } else {
        l = dig.k2
        var lb [16]byte
        copy(lb[:], m[:])

        lb[dig.nx] = 0x01

        lastblock[0] = binary.LittleEndian.Uint32(lb[0:])
        lastblock[1] = binary.LittleEndian.Uint32(lb[4:])
        lastblock[2] = binary.LittleEndian.Uint32(lb[8:])
        lastblock[3] = binary.LittleEndian.Uint32(lb[12:])
    }

    v0 ^= lastblock[0]
    v1 ^= lastblock[1]
    v2 ^= lastblock[2]
    v3 ^= lastblock[3]

    v0 ^= l[0]
    v1 ^= l[1]
    v2 ^= l[2]
    v3 ^= l[3]

    // permute
    for i := 0; i < dig.r; i++ {
        // round
        v0 += v1
        v2 += v3
        v1 = bits.RotateLeft32(v1, 5)
        v3 = bits.RotateLeft32(v3, 8)
        v1 ^= v0
        v3 ^= v2
        v0 = bits.RotateLeft32(v0, 16)
        v0 += v3
        v2 += v1
        v3 = bits.RotateLeft32(v3, 13)
        v1 = bits.RotateLeft32(v1, 7)
        v3 ^= v0
        v1 ^= v2
        v2 = bits.RotateLeft32(v2, 16)
    }

    v0 ^= l[0]
    v1 ^= l[1]
    v2 ^= l[2]
    v3 ^= l[3]

    dig.nx = 0

    dig.s[0], dig.s[1], dig.s[2], dig.s[3] = v0, v1, v2, v3
}
