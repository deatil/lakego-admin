package cast256

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func keyToUint32s(b []byte) []uint32 {
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

func uint32sToBytes(blk [4]uint32) [16]byte {
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

func getByte(x, n uint32) byte {
    return byte(x >> (8 * n))
}

func f1(y *uint32, x, kr, km uint32) {
    t := rotl32(km + x, kr)

    u := sbox[0][getByte(t, 3)]
    u ^= sbox[1][getByte(t, 2)]
    u -= sbox[2][getByte(t, 1)]
    u += sbox[3][getByte(t, 0)]

    (*y) ^= u
}

func f2(y *uint32, x, kr, km uint32) {
    t := rotl32(km ^ x, kr)

    u := sbox[0][getByte(t, 3)]
    u -= sbox[1][getByte(t, 2)]
    u += sbox[2][getByte(t, 1)]
    u ^= sbox[3][getByte(t, 0)]

    (*y) ^= u
}

func f3(y *uint32, x, kr, km uint32) {
    t := rotl32(km - x, kr)

    u := sbox[0][getByte(t, 3)]
    u += sbox[1][getByte(t, 2)]
    u ^= sbox[2][getByte(t, 1)]
    u -= sbox[3][getByte(t, 0)]

    (*y) ^= u
}

func f_rnd(x *[4]uint32, n uint32, l_key [96]uint32) {
    f1(&x[2], x[3], l_key[n],     l_key[n + 4])
    f2(&x[1], x[2], l_key[n + 1], l_key[n + 5])
    f3(&x[0], x[1], l_key[n + 2], l_key[n + 6])
    f1(&x[3], x[0], l_key[n + 3], l_key[n + 7])
}

func i_rnd(x *[4]uint32, n uint32, l_key [96]uint32) {
    f1(&x[3], x[0], l_key[n + 3], l_key[n + 7])
    f3(&x[0], x[1], l_key[n + 2], l_key[n + 6])
    f2(&x[1], x[2], l_key[n + 1], l_key[n + 5])
    f1(&x[2], x[3], l_key[n],     l_key[n + 4])
}

func k_rnd(k *[8]uint32, tr, tm [8]uint32) {
    f1(&k[6], k[7], tr[0], tm[0])
    f2(&k[5], k[6], tr[1], tm[1])
    f3(&k[4], k[5], tr[2], tm[2])
    f1(&k[3], k[4], tr[3], tm[3])
    f2(&k[2], k[3], tr[4], tm[4])
    f3(&k[1], k[2], tr[5], tm[5])
    f1(&k[0], k[1], tr[6], tm[6])
    f2(&k[7], k[0], tr[7], tm[7])
}
