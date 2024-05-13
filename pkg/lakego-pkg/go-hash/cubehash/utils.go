package cubehash

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

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

func rotl(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func round(x *[32]uint32) {
    for n := 0; n < 16; n++ {
        x[n+16] += x[n]
        x[n] = rotl(x[n], 7)
    }

    x[0], x[8] = x[8], x[0]
    x[1], x[9] = x[9], x[1]
    x[2], x[10] = x[10], x[2]
    x[3], x[11] = x[11], x[3]
    x[4], x[12] = x[12], x[4]
    x[5], x[13] = x[13], x[5]
    x[6], x[14] = x[14], x[6]
    x[7], x[15] = x[15], x[7]
    for n := 0; n < 16; n++ {
        x[n] ^= x[n+16]
    }

    x[16], x[18] = x[18], x[16]
    x[17], x[19] = x[19], x[17]
    x[20], x[22] = x[22], x[20]
    x[21], x[23] = x[23], x[21]
    x[24], x[26] = x[26], x[24]
    x[25], x[27] = x[27], x[25]
    x[28], x[30] = x[30], x[28]
    x[29], x[31] = x[31], x[29]

    for n := 0; n < 16; n++ {
        x[n+16] += x[n]
        x[n] = rotl(x[n], 11)
    }

    x[0], x[4] = x[4], x[0]
    x[1], x[5] = x[5], x[1]
    x[2], x[6] = x[6], x[2]
    x[3], x[7] = x[7], x[3]
    x[8], x[12] = x[12], x[8]
    x[9], x[13] = x[13], x[9]
    x[10], x[14] = x[14], x[10]
    x[11], x[15] = x[15], x[11]

    for n := 0; n < 16; n++ {
        x[n] ^= x[n+16]
    }

    x[16], x[17] = x[17], x[16]
    x[18], x[19] = x[19], x[18]
    x[20], x[21] = x[21], x[20]
    x[22], x[23] = x[23], x[22]
    x[24], x[25] = x[25], x[24]
    x[26], x[27] = x[27], x[26]
    x[28], x[29] = x[29], x[28]
    x[30], x[31] = x[31], x[30]
}
