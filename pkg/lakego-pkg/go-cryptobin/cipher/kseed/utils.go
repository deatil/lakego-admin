package kseed

import (
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

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

func bytesToUint32(inp []byte) (blk uint32) {
    if littleEndian {
        blk = binary.LittleEndian.Uint32(inp[0:])
    } else {
        blk = binary.BigEndian.Uint32(inp[0:])
    }

    return
}

func uint32ToBytes(blk uint32) [4]byte {
    var sav [4]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk)
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk)
    }

    return sav
}

func G(x uint32) uint32 {
    return (SS3[(x >> 24) & 255] ^
        SS2[(x >> 16) & 255] ^
        SS1[(x >> 8) & 255] ^
        SS0[ x & 255])
}

func F(L1, L2 *uint32, R1, R2, K1, K2 uint32) {
   T2 := G((R1 ^ K1) ^ (R2 ^ K2))
   T := G( G(T2 + (R1 ^ K1)) + T2 )

   (*L2) ^= T

   (*L1) ^= (T + G(T2 + (R1 ^ K1)))
}

func rounds(P []uint32, K []uint32) {
    var i int32

    for i = 0; i < 16; i += 2 {
        F(&P[0], &P[1], P[2], P[3], K[0], K[1])
        F(&P[2], &P[3], P[0], P[1], K[2], K[3])

        K = K[4:]
    }
}
