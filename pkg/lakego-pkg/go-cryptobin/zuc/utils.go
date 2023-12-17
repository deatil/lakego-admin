package zuc

import (
    "strconv"
    "encoding/binary"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/zuc: invalid key size " + strconv.Itoa(int(k))
}

type IVSizeError int

func (k IVSizeError) Error() string {
    return "cryptobin/zuc: invalid iv size " + strconv.Itoa(int(k))
}

func MemsetByte(a []byte, v byte) {
    if len(a) == 0 {
        return
    }

    a[0] = v
    for bp := 1; bp < len(a); bp *= 2 {
        copy(a[bp:], a[:bp])
    }
}

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

func GETU32(ptr []byte) uint32 {
    return uint32(ptr[0]) << 24 |
           uint32(ptr[1]) << 16 |
           uint32(ptr[2]) <<  8 |
           uint32(ptr[3])
}

func PUTU32(ptr []byte, a uint32) {
    ptr[0] = byte(a >> 24)
    ptr[1] = byte(a >> 16)
    ptr[2] = byte(a >>  8)
    ptr[3] = byte(a)
}

func ADD31(a *uint32, b uint32) {
    (*a) += b
    (*a) = ((*a) & 0x7fffffff) + ((*a) >> 31)
}

func ROT31(a, k uint32) uint32 {
    return ((a << k) | (a >> (31 - k))) & 0x7FFFFFFF
}

func ROT32(a, k uint32) uint32 {
    return (a << k) | (a >> (32 - k))
}

func L1(X uint32) uint32 {
    return (X ^
            ROT32(X,  2) ^
            ROT32(X, 10) ^
            ROT32(X, 18) ^
            ROT32(X, 24))
}

func L2(X uint32) uint32 {
    return (X ^
            ROT32(X,  8) ^
            ROT32(X, 14) ^
            ROT32(X, 22) ^
            ROT32(X, 30))
}

func LFSRWithInitialisationMode(u uint32, LFSR []uint32) {
    V := LFSR[0]

    ADD31(&V, ROT31(LFSR[0], 8))
    ADD31(&V, ROT31(LFSR[4], 20))
    ADD31(&V, ROT31(LFSR[10], 21))
    ADD31(&V, ROT31(LFSR[13], 17))
    ADD31(&V, ROT31(LFSR[15], 15))
    ADD31(&V, u)

    for j := 0; j < 15; j++ {
        LFSR[j] = LFSR[j + 1]
    }

    LFSR[15] = V
}

func LFSRWithWorkMode(LFSR []uint32) {
    var j int32
    var a uint64 = uint64(LFSR[0])

    a += uint64(LFSR[0]) << 8
    a += uint64(LFSR[4]) << 20
    a += uint64(LFSR[10]) << 21
    a += uint64(LFSR[13]) << 17
    a += uint64(LFSR[15]) << 15
    a = (a & 0x7fffffff) + (a >> 31)

    V := uint32((a & 0x7fffffff) + (a >> 31))

    for j = 0; j < 15; j++ {
        LFSR[j] = LFSR[j + 1]
    }

    LFSR[15] = V
}

func BitReconstruction2(X1, X2 *uint32, LFSR []uint32) {
    (*X1) = ((LFSR[11] & 0xFFFF) << 16) | (LFSR[9] >> 15)
    (*X2) = ((LFSR[7] & 0xFFFF) << 16) | (LFSR[5] >> 15)
}

func BitReconstruction3(X0, X1, X2 *uint32, LFSR []uint32) {
    (*X0) = ((LFSR[15] & 0x7FFF8000) << 1) | (LFSR[14] & 0xFFFF)

    BitReconstruction2(X1, X2, LFSR)
}

func BitReconstruction4(X0, X1, X2, X3 *uint32, LFSR []uint32) {
    BitReconstruction3(X0, X1, X2, LFSR)

    (*X3) = ((LFSR[2] & 0xFFFF) << 16) | (LFSR[0] >> 15)
}

func MAKEU31(k uint8, d uint32, iv uint8) uint32 {
    return uint32(k) << 23 |
           uint32(d) <<  8 |
           uint32(iv)
}

func MAKEU32(a, b, c, d uint8) uint32 {
    return uint32(a) << 24 |
           uint32(b) << 16 |
           uint32(c) <<  8 |
           uint32(d)
}

func F_(R1, R2 *uint32, X1, X2 uint32) {
    W1 := (*R1) + X1
    W2 := (*R2) ^ X2

    U := L1((W1 << 16) | (W2 >> 16))
    V := L2((W2 << 16) | (W1 >> 16))

    (*R1) = MAKEU32(
            S0[U >> 24],
            S1[(U >> 16) & 0xFF],
            S0[(U >> 8) & 0xFF],
            S1[U & 0xFF],
        )
    (*R2) = MAKEU32(
            S0[V >> 24],
            S1[(V >> 16) & 0xFF],
            S0[(V >> 8) & 0xFF],
            S1[V & 0xFF],
        )
}

func F(R1, R2 *uint32, X0, X1, X2 uint32) uint32 {
    r := (X0 ^ (*R1)) + (*R2)

    F_(R1, R2, X1, X2)

    return r
}

func EEA_ENCRYPT_NWORDS(nbits int) int {
    return (nbits + 31) / 32
}

func EEA_ENCRYPT_NBYTES(nbits int) int {
    return EEA_ENCRYPT_NWORDS(nbits) * 4
}
