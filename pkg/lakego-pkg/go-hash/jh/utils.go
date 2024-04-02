package jh

import (
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func GETU64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func PUTU64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
    }
}

func PUTU64BE(ptr []byte, a uint64) {
    binary.BigEndian.PutUint64(ptr, a)
}

func bytesToUint64s(b []byte) []uint64 {
    size := len(b) / 8
    dst := make([]uint64, size)

    for i := 0; i < size; i++ {
        j := i * 8

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint64(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint64(b[j:])
        }
    }

    return dst
}

func uint64sToBytes(w []uint64) []byte {
    size := len(w) * 8
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 8

        if littleEndian {
            binary.LittleEndian.PutUint64(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint64(dst[j:], w[i])
        }
    }

    return dst
}

/* swapping bit 2i with bit 2i+1 of 64-bit x */
func SWAP1(x *uint64) {
    (*x) = ((*x) & 0x5555555555555555) << 1 | ((*x) & 0xaaaaaaaaaaaaaaaa) >> 1
}

/* swapping bits 4i||4i+1 with bits 4i+2||4i+3 of 64-bit x */
func SWAP2(x *uint64) {
    (*x) = ((*x) & 0x3333333333333333) << 2 | ((*x) & 0xcccccccccccccccc) >> 2
}

/* swapping bits 8i||8i+1||8i+2||8i+3 with bits 8i+4||8i+5||8i+6||8i+7 of 64-bit x */
func SWAP4(x *uint64) {
    (*x) = ((*x) & 0x0f0f0f0f0f0f0f0f) << 4 | ((*x) & 0xf0f0f0f0f0f0f0f0) >> 4
}

/* swapping bits 16i||16i+1||......||16i+7  with bits 16i+8||16i+9||......||16i+15 of 64-bit x */
func SWAP8(x *uint64) {
    (*x) = ((*x) & 0x00ff00ff00ff00ff) << 8 | ((*x) & 0xff00ff00ff00ff00) >> 8
}

/* swapping bits 32i||32i+1||......||32i+15 with bits 32i+16||32i+17||......||32i+31 of 64-bit x */
func SWAP16(x *uint64) {
    (*x) = ((*x) & 0x0000ffff0000ffff) << 16 | ((*x) & 0xffff0000ffff0000) >> 16
}

/* swapping bits 64i||64i+1||......||64i+31 with bits 64i+32||64i+33||......||64i+63 of 64-bit x */
func SWAP32(x *uint64) {
    (*x) = (*x) << 32 | (*x) >> 32
}

/* Two Sboxes are computed in parallel, each Sbox implements S0 and S1, selected by a constant bit
   The reason to compute two Sboxes in parallel is to try to fully utilize the parallel processing power */
func SS(m0, m1, m2, m3, m4, m5, m6, m7 *uint64, cc0, cc1 uint64) {
    var temp0, temp1 uint64

    (*m3) = ^(*m3)
    (*m7) = ^(*m7)
    (*m0) ^= ((^(*m2)) & (cc0))
    (*m4) ^= ((^(*m6)) & (cc1))
    temp0 = (cc0) ^ ((*m0) & (*m1))
    temp1 = (cc1) ^ ((*m4) & (*m5))
    (*m0) ^= ((*m2) & (*m3))
    (*m4) ^= ((*m6) & (*m7))
    (*m3) ^= ((^(*m1)) & (*m2))
    (*m7) ^= ((^(*m5)) & (*m6))
    (*m1) ^= ((*m0) & (*m2))
    (*m5) ^= ((*m4) & (*m6))
    (*m2) ^= ((*m0) & (^(*m3)))
    (*m6) ^= ((*m4) & (^(*m7)))
    (*m0) ^= ((*m1) | (*m3))
    (*m4) ^= ((*m5) | (*m7))
    (*m3) ^= ((*m1) & (*m2))
    (*m7) ^= ((*m5) & (*m6))
    (*m1) ^= (temp0 & (*m0))
    (*m5) ^= (temp1 & (*m4))
    (*m2) ^= temp0
    (*m6) ^= temp1
}

/* The MDS transform */
func L(m0, m1, m2, m3, m4, m5, m6, m7 *uint64) {
    (*m4) ^= (*m1)
    (*m5) ^= (*m2)
    (*m6) ^= (*m0) ^ (*m3)
    (*m7) ^= (*m0)
    (*m0) ^= (*m5)
    (*m1) ^= (*m6)
    (*m2) ^= (*m4) ^ (*m7)
    (*m3) ^= (*m4)
}
