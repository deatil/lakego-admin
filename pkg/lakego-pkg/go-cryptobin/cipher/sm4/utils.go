package sm4

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

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

func rotl(a uint32, n uint32) uint32 {
    return bits.RotateLeft32(a, int(n))
}

func tNonLinSub(X uint32) uint32 {
    var t uint32 = 0

    t |= uint32(sbox[byte(X >> 24)]) << 24
    t |= uint32(sbox[byte(X >> 16)]) << 16
    t |= uint32(sbox[byte(X >>  8)]) <<  8
    t |= uint32(sbox[byte(X      )])

    return t
}

func tSlow(X uint32) uint32 {
    var t uint32 = tNonLinSub(X)

    /*
     * L linear transform
     */
    return t ^
           rotl(t, 2) ^
           rotl(t, 10) ^
           rotl(t, 18) ^
           rotl(t, 24)
}

func t(X uint32) uint32 {
    return sbox_t0[byte(X >> 24)] ^
           sbox_t1[byte(X >> 16)] ^
           sbox_t2[byte(X >>  8)] ^
           sbox_t3[byte(X      )]
}

func keySub(X uint32) uint32 {
    var t uint32 = tNonLinSub(X)

    return t ^ rotl(t, 13) ^ rotl(t, 23)
}
