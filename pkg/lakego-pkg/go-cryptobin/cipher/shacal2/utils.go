package shacal2

import (
    "math/bits"
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.BigEndian.Uint32(b[j:])
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        binary.BigEndian.PutUint32(dst[j:], w[i])
    }

    return dst
}

func rotr(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, 32 - n)
}

func sigma(x uint32, r1, r2, s int) uint32 {
   return rotr(x, r1) ^ rotr(x, r2) ^ (x >> s)
}

func rho(x uint32, r1, r2, r3 int) uint32 {
    return rotr(x, r1) ^ rotr(x, r2) ^ rotr(x, r3)
}

func choose(mask, a, b uint32) uint32 {
    return b ^ (mask & (a ^ b))
}

func majority(a, b, c uint32) uint32 {
    return choose(a ^ b, c, b)
}

func fwd(
    A, B, C uint32,
    D *uint32,
    E, F, G uint32,
    H *uint32,
    RK uint32,
) {
    A_rho := rho(A, 2, 13, 22)
    E_rho := rho(E, 6, 11, 25)

    (*H) += E_rho + choose(E, F, G) + RK
    (*D) += (*H)
    (*H) += A_rho + majority(A, B, C)
}

func rev(
    A, B, C uint32,
    D *uint32,
    E, F, G uint32,
    H *uint32,
    RK uint32,
) {
    A_rho := rho(A, 2, 13, 22)
    E_rho := rho(E, 6, 11, 25)

   (*H) -= A_rho + majority(A, B, C)
   (*D) -= (*H)
   (*H) -= E_rho + choose(E, F, G) + RK
}
