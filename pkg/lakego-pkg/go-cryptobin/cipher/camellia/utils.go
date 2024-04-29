package camellia

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func getu64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func putu64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
    }
}

func rotl128(k [2]uint64, rot uint) (hi, lo uint64) {
    if rot > 64 {
        rot -= 64
        k[0], k[1] = k[1], k[0]
    }

    t := k[0] >> (64 - rot)
    hi = (k[0] << rot) | (k[1] >> (64 - rot))
    lo = (k[1] << rot) | t

    return hi, lo
}

func f(fin, ke uint64) uint64 {
    var x uint64
    x = fin ^ ke
    t1 := sbox1[uint8(x>>56)]
    t2 := sbox2[uint8(x>>48)]
    t3 := sbox3[uint8(x>>40)]
    t4 := sbox4[uint8(x>>32)]
    t5 := sbox2[uint8(x>>24)]
    t6 := sbox3[uint8(x>>16)]
    t7 := sbox4[uint8(x>>8)]
    t8 := sbox1[uint8(x)]
    y1 := t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    y2 := t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    y3 := t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    y4 := t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    y5 := t1 ^ t2 ^ t6 ^ t7 ^ t8
    y6 := t2 ^ t3 ^ t5 ^ t7 ^ t8
    y7 := t3 ^ t4 ^ t5 ^ t6 ^ t8
    y8 := t1 ^ t4 ^ t5 ^ t6 ^ t7
    return uint64(y1)<<56 | uint64(y2)<<48 | uint64(y3)<<40 | uint64(y4)<<32 | uint64(y5)<<24 | uint64(y6)<<16 | uint64(y7)<<8 | uint64(y8)
}

func fl(flin, ke uint64) uint64 {
    x1 := uint32(flin >> 32)
    x2 := uint32(flin & 0xffffffff)
    k1 := uint32(ke >> 32)
    k2 := uint32(ke & 0xffffffff)
    x2 = x2 ^ bits.RotateLeft32(x1&k1, 1)
    x1 = x1 ^ (x2 | k2)
    return uint64(x1)<<32 | uint64(x2)
}

func flinv(flin, ke uint64) uint64 {
    y1 := uint32(flin >> 32)
    y2 := uint32(flin & 0xffffffff)
    k1 := uint32(ke >> 32)
    k2 := uint32(ke & 0xffffffff)
    y1 = y1 ^ (y2 | k2)
    y2 = y2 ^ bits.RotateLeft32(y1&k1, 1)
    return uint64(y1)<<32 | uint64(y2)
}
