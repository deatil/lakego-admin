package sm4

import (
    "math/bits"
    "encoding/binary"
)

func rotl(a uint32, n uint32) uint32 {
    return bits.RotateLeft32(a, int(n))
}

func T_non_lin_sub(X uint32) uint32 {
    var t uint32 = 0

    t |= uint32(Sbox[byte(X >> 24)]) << 24
    t |= uint32(Sbox[byte(X >> 16)]) << 16
    t |= uint32(Sbox[byte(X >>  8)]) <<  8
    t |= uint32(Sbox[byte(X      )])

    return t
}

func T_slow(X uint32) uint32 {
    var t uint32 = T_non_lin_sub(X)

    /*
     * L linear transform
     */
    return t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24)
}

func T(X uint32) uint32 {
    return SBOX_T0[byte(X >> 24)] ^
           SBOX_T1[byte(X >> 16)] ^
           SBOX_T2[byte(X >>  8)] ^
           SBOX_T3[byte(X      )]
}

func key_sub(X uint32) uint32 {
    var t uint32 = T_non_lin_sub(X)

    return t ^ rotl(t, 13) ^ rotl(t, 23)
}

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
