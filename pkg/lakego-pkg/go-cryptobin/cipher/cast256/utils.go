package cast256

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func bytesToUint32s(inp []byte) [4]uint32 {
    var blk [4]uint32

    if littleEndian {
        blk[0] = binary.LittleEndian.Uint32(inp[0:])
        blk[1] = binary.LittleEndian.Uint32(inp[4:])
        blk[2] = binary.LittleEndian.Uint32(inp[8:])
        blk[3] = binary.LittleEndian.Uint32(inp[12:])
    } else {
        blk[0] = binary.BigEndian.Uint32(inp[0:])
        blk[1] = binary.BigEndian.Uint32(inp[4:])
        blk[2] = binary.BigEndian.Uint32(inp[8:])
        blk[3] = binary.BigEndian.Uint32(inp[12:])
    }

    return blk
}

func Uint32sToBytes(blk [4]uint32) [16]byte {
    var sav [16]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk[0])
        binary.LittleEndian.PutUint32(sav[4:], blk[1])
        binary.LittleEndian.PutUint32(sav[8:], blk[2])
        binary.LittleEndian.PutUint32(sav[12:], blk[3])
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk[0])
        binary.BigEndian.PutUint32(sav[4:], blk[1])
        binary.BigEndian.PutUint32(sav[8:], blk[2])
        binary.BigEndian.PutUint32(sav[12:], blk[3])
    }

    return sav
}

func rotl32(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotr32(x, n uint32) uint32 {
    return rotl32(x, 32 - n);
}

func byteswap32(x uint32) uint32 {
    return ((rotl32(x, 8) & 0x00ff00ff) | (rotr32(x, 8) & 0xff00ff00))
}

func getByte(x, n uint32) uint8 {
    return uint8(x >> (8 * n))
}

func f1(y, x, kr, km uint32) uint32 {
    t := rotl32(km + x, kr)

    u := cast256_sbox[0][getByte(t, 3)]
    u ^= cast256_sbox[1][getByte(t, 2)]
    u -= cast256_sbox[2][getByte(t, 1)]
    u += cast256_sbox[3][getByte(t, 0)]

    y ^= u

    return y
}

func f2(y, x, kr, km uint32) uint32 {
    t := rotl32(km ^ x, kr)

    u := cast256_sbox[0][getByte(t, 3)]
    u -= cast256_sbox[1][getByte(t, 2)]
    u += cast256_sbox[2][getByte(t, 1)]
    u ^= cast256_sbox[3][getByte(t, 0)]

    y ^= u

    return y
}

func f3(y, x, kr, km uint32) uint32 {
    t := rotl32(km - x, kr)

    u := cast256_sbox[0][getByte(t, 3)]
    u += cast256_sbox[1][getByte(t, 2)]
    u ^= cast256_sbox[2][getByte(t, 1)]
    u -= cast256_sbox[3][getByte(t, 0)]

    y ^= u

    return y
}

func f_rnd(x [4]uint32, n uint32, l_key [96]uint32) [4]uint32 {
    x[2] = f1(x[2], x[3], l_key[n],     l_key[n + 4])
    x[1] = f2(x[1], x[2], l_key[n + 1], l_key[n + 5])
    x[0] = f3(x[0], x[1], l_key[n + 2], l_key[n + 6])
    x[3] = f1(x[3], x[0], l_key[n + 3], l_key[n + 7])

    return x
}

func i_rnd(x [4]uint32, n uint32, l_key [96]uint32) [4]uint32 {
    x[3] = f1(x[3], x[0], l_key[n + 3], l_key[n + 7])
    x[0] = f3(x[0], x[1], l_key[n + 2], l_key[n + 6])
    x[1] = f2(x[1], x[2], l_key[n + 1], l_key[n + 5])
    x[2] = f1(x[2], x[3], l_key[n],     l_key[n + 4])

    return x
}

func k_rnd(k, tr, tm [8]uint32) [8]uint32 {
    k[6] = f1(k[6], k[7], tr[0], tm[0])
    k[5] = f2(k[5], k[6], tr[1], tm[1])
    k[4] = f3(k[4], k[5], tr[2], tm[2])
    k[3] = f1(k[3], k[4], tr[3], tm[3])
    k[2] = f2(k[2], k[3], tr[4], tm[4])
    k[1] = f3(k[1], k[2], tr[5], tm[5])
    k[0] = f1(k[0], k[1], tr[6], tm[6])
    k[7] = f2(k[7], k[0], tr[7], tm[7])

    return k
}
