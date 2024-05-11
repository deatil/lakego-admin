package kuznyechik

import (
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

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

func ls(x1, x2 uint64) (t1, t2 uint64) {
    t1 = t[0][uint8(x1)][0] ^ t[1][uint8(x1>>8)][0] ^ t[2][uint8(x1>>16)][0] ^ t[3][uint8(x1>>24)][0] ^ t[4][uint8(x1>>32)][0] ^ t[5][uint8(x1>>40)][0] ^ t[6][uint8(x1>>48)][0] ^ t[7][uint8(x1>>56)][0] ^ t[8][uint8(x2)][0] ^ t[9][uint8(x2>>8)][0] ^ t[10][uint8(x2>>16)][0] ^ t[11][uint8(x2>>24)][0] ^ t[12][uint8(x2>>32)][0] ^ t[13][uint8(x2>>40)][0] ^ t[14][uint8(x2>>48)][0] ^ t[15][uint8(x2>>56)][0]
    t2 = t[0][uint8(x1)][1] ^ t[1][uint8(x1>>8)][1] ^ t[2][uint8(x1>>16)][1] ^ t[3][uint8(x1>>24)][1] ^ t[4][uint8(x1>>32)][1] ^ t[5][uint8(x1>>40)][1] ^ t[6][uint8(x1>>48)][1] ^ t[7][uint8(x1>>56)][1] ^ t[8][uint8(x2)][1] ^ t[9][uint8(x2>>8)][1] ^ t[10][uint8(x2>>16)][1] ^ t[11][uint8(x2>>24)][1] ^ t[12][uint8(x2>>32)][1] ^ t[13][uint8(x2>>40)][1] ^ t[14][uint8(x2>>48)][1] ^ t[15][uint8(x2>>56)][1]
    return
}

func ils(x1, x2 uint64) (t1, t2 uint64) {
    t1 = it[0][uint8(x1)][0] ^ it[1][uint8(x1>>8)][0] ^ it[2][uint8(x1>>16)][0] ^ it[3][uint8(x1>>24)][0] ^ it[4][uint8(x1>>32)][0] ^ it[5][uint8(x1>>40)][0] ^ it[6][uint8(x1>>48)][0] ^ it[7][uint8(x1>>56)][0] ^ it[8][uint8(x2)][0] ^ it[9][uint8(x2>>8)][0] ^ it[10][uint8(x2>>16)][0] ^ it[11][uint8(x2>>24)][0] ^ it[12][uint8(x2>>32)][0] ^ it[13][uint8(x2>>40)][0] ^ it[14][uint8(x2>>48)][0] ^ it[15][uint8(x2>>56)][0]
    t2 = it[0][uint8(x1)][1] ^ it[1][uint8(x1>>8)][1] ^ it[2][uint8(x1>>16)][1] ^ it[3][uint8(x1>>24)][1] ^ it[4][uint8(x1>>32)][1] ^ it[5][uint8(x1>>40)][1] ^ it[6][uint8(x1>>48)][1] ^ it[7][uint8(x1>>56)][1] ^ it[8][uint8(x2)][1] ^ it[9][uint8(x2>>8)][1] ^ it[10][uint8(x2>>16)][1] ^ it[11][uint8(x2>>24)][1] ^ it[12][uint8(x2>>32)][1] ^ it[13][uint8(x2>>40)][1] ^ it[14][uint8(x2>>48)][1] ^ it[15][uint8(x2>>56)][1]
    return
}

func ilss(x1, x2 uint64) (t1, t2 uint64) {
    t1 = it[0][s[uint8(x1)]][0] ^ it[1][s[uint8(x1>>8)]][0] ^ it[2][s[uint8(x1>>16)]][0] ^ it[3][s[uint8(x1>>24)]][0] ^ it[4][s[uint8(x1>>32)]][0] ^ it[5][s[uint8(x1>>40)]][0] ^ it[6][s[uint8(x1>>48)]][0] ^ it[7][s[uint8(x1>>56)]][0] ^ it[8][s[uint8(x2)]][0] ^ it[9][s[uint8(x2>>8)]][0] ^ it[10][s[uint8(x2>>16)]][0] ^ it[11][s[uint8(x2>>24)]][0] ^ it[12][s[uint8(x2>>32)]][0] ^ it[13][s[uint8(x2>>40)]][0] ^ it[14][s[uint8(x2>>48)]][0] ^ it[15][s[uint8(x2>>56)]][0]
    t2 = it[0][s[uint8(x1)]][1] ^ it[1][s[uint8(x1>>8)]][1] ^ it[2][s[uint8(x1>>16)]][1] ^ it[3][s[uint8(x1>>24)]][1] ^ it[4][s[uint8(x1>>32)]][1] ^ it[5][s[uint8(x1>>40)]][1] ^ it[6][s[uint8(x1>>48)]][1] ^ it[7][s[uint8(x1>>56)]][1] ^ it[8][s[uint8(x2)]][1] ^ it[9][s[uint8(x2>>8)]][1] ^ it[10][s[uint8(x2>>16)]][1] ^ it[11][s[uint8(x2>>24)]][1] ^ it[12][s[uint8(x2>>32)]][1] ^ it[13][s[uint8(x2>>40)]][1] ^ it[14][s[uint8(x2>>48)]][1] ^ it[15][s[uint8(x2>>56)]][1]
    return
}

func isi(val uint64) (res uint64) {
    // Apply "is" byte-by-byte
    var i uint
    for i = 0; i < 64; i += 8 {
        res |= uint64(is[uint8(val>>i)]) << i
    }
    return
}

func f(k00, k01, k10, k11 uint64, i int) (o00, o01, o10, o11 uint64) {
    o10 = k00
    o11 = k01
    k00 ^= c[i][0]
    k01 ^= c[i][1]
    o00, o01 = ls(k00, k01)
    o00 ^= k10
    o01 ^= k11
    return
}

func fk(k00, k01, k10, k11 uint64, ist int) (o00, i01, o10, o11 uint64) {
    var t00, t01, t10, t11 uint64
    for i := 0; i < 8; i += 2 {
        t00, t01, t10, t11 = f(k00, k01, k10, k11, i+ist)
        k00, k01, k10, k11 = f(t00, t01, t10, t11, i+1+ist)
    }

    return k00, k01, k10, k11
}
