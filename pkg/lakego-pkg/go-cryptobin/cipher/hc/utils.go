package hc

import (
    "math/bits"
    "crypto/subtle"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

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

func tmin(a, b int) int {
    if a < b {
        return a
    }

    return b
}

func rotatel32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func rotater32(x uint32, n int) uint32 {
    return rotatel32(x, 32 - n)
}

func xor_block_512(in []byte, prev []byte, out []byte) {
    subtle.XORBytes(out, in[:64], prev[:64])
}

func f1(x uint32) uint32 {
    return rotater32(x, 7) ^ rotater32(x, 18) ^ (x >> 3)
}

func f2(x uint32) uint32 {
    return rotater32(x, 17) ^ rotater32(x, 19) ^ (x >> 10)
}

func g1(x uint32, y uint32, Q []uint32) uint32 {
    return (rotater32(x, 10) ^ rotater32(y, 23)) + Q[(x ^ y) & 0x3ff]
}

func h1(x uint32, Q []uint32) uint32 {
    return Q[uint32(byte(x))] + Q[256 + uint32(byte(x >> 8))] + Q[512 + uint32(byte(x >> 16))] + Q[768 + uint32(byte(x >> 24))]
}

func P32(P, Q, X []uint32, i, x uint32) {
    P[i + x] = P[i + x] + X[(x + 6) % 16] + g1(X[(x + 13) % 16], P[i + 1 + x], Q)
    X[x] = P[i + x]
}

func P32L(P, Q, X []uint32, i, x uint32) {
    var Pindex uint32
    if i == 1008 {
        Pindex = 0
    } else {
        Pindex = i + 1 + x
    }

    P[i + x] = P[i + x] + X[(x + 6) % 16] + g1(X[(x + 13) % 16], P[Pindex], Q)
    X[x] = P[i + x]
}

func P32_block(P, Q, X, block []uint32, i, x uint32) {
    P32(P, Q, X, i, x)
    block[x] = h1(X[(x + 4) % 16], Q) ^ P[i + x]
}

func P32L_block(P, Q, X, block []uint32, i, x uint32) {
    P32L(P, Q, X, i, x)
    block[x] = h1(X[(x + 4) % 16], Q) ^ P[i + x]
}

func gen_block_block(P, Q, X, block []uint32, i uint32) {
    P32_block(P, Q, X, block, i, 0)
    P32_block(P, Q, X, block, i, 1)
    P32_block(P, Q, X, block, i, 2)
    P32_block(P, Q, X, block, i, 3)
    P32_block(P, Q, X, block, i, 4)
    P32_block(P, Q, X, block, i, 5)
    P32_block(P, Q, X, block, i, 6)
    P32_block(P, Q, X, block, i, 7)
    P32_block(P, Q, X, block, i, 8)
    P32_block(P, Q, X, block, i, 9)
    P32_block(P, Q, X, block, i, 10)
    P32_block(P, Q, X, block, i, 11)
    P32_block(P, Q, X, block, i, 12)
    P32_block(P, Q, X, block, i, 13)
    P32_block(P, Q, X, block, i, 14)
    P32L_block(P, Q, X, block, i, 15)
}

func gen_block(P, Q, X []uint32, i uint32) {
    P32(P, Q, X, i, 0)
    P32(P, Q, X, i, 1)
    P32(P, Q, X, i, 2)
    P32(P, Q, X, i, 3)
    P32(P, Q, X, i, 4)
    P32(P, Q, X, i, 5)
    P32(P, Q, X, i, 6)
    P32(P, Q, X, i, 7)
    P32(P, Q, X, i, 8)
    P32(P, Q, X, i, 9)
    P32(P, Q, X, i, 10)
    P32(P, Q, X, i, 11)
    P32(P, Q, X, i, 12)
    P32(P, Q, X, i, 13)
    P32(P, Q, X, i, 14)
    P32L(P, Q, X, i, 15)
}

func generate_block_block(P, Q, X, Y, block_ []uint32, words *uint32) {
    if (*words) < 1024 {
        gen_block_block(P, Q, X, block_, (*words))
        (*words) += 16
    } else {
        gen_block_block(Q, P, Y, block_, (*words) - 1024)
        (*words) += 16
        if (*words) == 2048 {
            (*words) = 0
        }
    }
}

func generate_block(P, Q, X, Y []uint32, words *uint32) {
    if (*words) < 1024 {
        gen_block(P, Q, X, (*words))
        (*words) += 16
    } else {
        gen_block(Q, P, Y, (*words) - 1024)
        (*words) += 16
        if (*words) == 2048 {
            (*words) = 0
        }
    }
}

// =========

func g1_128(x, y, z uint32) uint32 {
    return (rotater32(x, 10) ^ rotater32(z, 23)) + rotater32(y, 8)
}

func g2_128(x, y, z uint32) uint32 {
    return (rotatel32(x, 10) ^ rotatel32(z, 23)) + rotatel32(y, 8)
}

func h1_128(x uint32, Q []uint32) uint32 {
    return Q[uint32(byte(x))] + Q[256 + uint32(byte(x >> 16))]
}

func P32_128_P(P, Q, X []uint32, i, x uint32) {
    P[i + x] = (P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x])) ^ h1_128(X[(x + 4) % 16], Q)
    X[x] = P[i + x]
}

func P32_128L_P(P, Q, X []uint32, i, x uint32) {
    var Iindex uint32
    if i == 496 {
        Iindex = 0
    } else {
        Iindex = i + 1 + x
    }

    P[i + x] = (P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[Iindex])) ^ h1_128(X[(x + 4) % 16], Q)
    X[x] = P[i + x]
}

func P32_128_P_block(P, Q, X, block []uint32, i, x uint32) {
    P[i + x] = P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x])
    X[x] = P[i + x]
    block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x]
}

func P32_128L_P_block(P, Q, X, block []uint32, i, x uint32) {
    var Iindex uint32
    if i == 496 {
        Iindex = 0
    } else {
        Iindex = i + 1 + x
    }

    P[i + x] = P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[Iindex])
    X[x] = P[i + x]
    block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x]
}

func gen_block_128_P_block(P, Q, X, block []uint32, i uint32) {
    P32_128_P_block(P, Q, X, block, i, 0)
    P32_128_P_block(P, Q, X, block, i, 1)
    P32_128_P_block(P, Q, X, block, i, 2)
    P32_128_P_block(P, Q, X, block, i, 3)
    P32_128_P_block(P, Q, X, block, i, 4)
    P32_128_P_block(P, Q, X, block, i, 5)
    P32_128_P_block(P, Q, X, block, i, 6)
    P32_128_P_block(P, Q, X, block, i, 7)
    P32_128_P_block(P, Q, X, block, i, 8)
    P32_128_P_block(P, Q, X, block, i, 9)
    P32_128_P_block(P, Q, X, block, i, 10)
    P32_128_P_block(P, Q, X, block, i, 11)
    P32_128_P_block(P, Q, X, block, i, 12)
    P32_128_P_block(P, Q, X, block, i, 13)
    P32_128_P_block(P, Q, X, block, i, 14)
    P32_128L_P_block(P, Q, X, block, i, 15)
}

func P32_128_Q(P, Q, X []uint32, i, x uint32) {
    P[i + x] = (P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x])) ^ h1_128(X[(x + 4) % 16], Q)
    X[x] = P[i + x]
}

func P32_128L_Q(P, Q, X []uint32, i, x uint32) {
    var Iindex uint32
    if i == 496 {
        Iindex = 0
    } else {
        Iindex = i + 1 + x
    }

    P[i + x] = (P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[Iindex])) ^ h1_128(X[(x + 4) % 16], Q)
    X[x] = P[i + x]
}

func P32_128_Q_block(P, Q, X, block []uint32, i, x uint32) {
    P[i + x] = P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x])
    X[x] = P[i + x]
    block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x]
}

func P32_128L_Q_block(P, Q, X, block []uint32, i, x uint32) {
    var Iindex uint32
    if i == 496 {
        Iindex = 0
    } else {
        Iindex = i + 1 + x
    }

    P[i + x] = P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[Iindex]);
    X[x] = P[i + x];
    block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x];
}

func gen_block_128_P(P, Q, X []uint32, i uint32) {
    P32_128_P(P, Q, X, i, 0)
    P32_128_P(P, Q, X, i, 1)
    P32_128_P(P, Q, X, i, 2)
    P32_128_P(P, Q, X, i, 3)
    P32_128_P(P, Q, X, i, 4)
    P32_128_P(P, Q, X, i, 5)
    P32_128_P(P, Q, X, i, 6)
    P32_128_P(P, Q, X, i, 7)
    P32_128_P(P, Q, X, i, 8)
    P32_128_P(P, Q, X, i, 9)
    P32_128_P(P, Q, X, i, 10)
    P32_128_P(P, Q, X, i, 11)
    P32_128_P(P, Q, X, i, 12)
    P32_128_P(P, Q, X, i, 13)
    P32_128_P(P, Q, X, i, 14)
    P32_128L_P(P, Q, X, i, 15)
}

func gen_block_128_Q_block(P, Q, X, block []uint32, i uint32) {
    P32_128_Q_block(P, Q, X, block, i, 0)
    P32_128_Q_block(P, Q, X, block, i, 1)
    P32_128_Q_block(P, Q, X, block, i, 2)
    P32_128_Q_block(P, Q, X, block, i, 3)
    P32_128_Q_block(P, Q, X, block, i, 4)
    P32_128_Q_block(P, Q, X, block, i, 5)
    P32_128_Q_block(P, Q, X, block, i, 6)
    P32_128_Q_block(P, Q, X, block, i, 7)
    P32_128_Q_block(P, Q, X, block, i, 8)
    P32_128_Q_block(P, Q, X, block, i, 9)
    P32_128_Q_block(P, Q, X, block, i, 10)
    P32_128_Q_block(P, Q, X, block, i, 11)
    P32_128_Q_block(P, Q, X, block, i, 12)
    P32_128_Q_block(P, Q, X, block, i, 13)
    P32_128_Q_block(P, Q, X, block, i, 14)
    P32_128L_Q_block(P, Q, X, block, i, 15)
}

func gen_block_128_Q(P, Q, X []uint32, i uint32) {
    P32_128_Q(P, Q, X, i, 0)
    P32_128_Q(P, Q, X, i, 1)
    P32_128_Q(P, Q, X, i, 2)
    P32_128_Q(P, Q, X, i, 3)
    P32_128_Q(P, Q, X, i, 4)
    P32_128_Q(P, Q, X, i, 5)
    P32_128_Q(P, Q, X, i, 6)
    P32_128_Q(P, Q, X, i, 7)
    P32_128_Q(P, Q, X, i, 8)
    P32_128_Q(P, Q, X, i, 9)
    P32_128_Q(P, Q, X, i, 10)
    P32_128_Q(P, Q, X, i, 11)
    P32_128_Q(P, Q, X, i, 12)
    P32_128_Q(P, Q, X, i, 13)
    P32_128_Q(P, Q, X, i, 14)
    P32_128L_Q(P, Q, X, i, 15)
}

func generate_block_128_block(P, Q, X, Y, block_ []uint32, words *uint32) {
    if (*words) < 512 {
        gen_block_128_P_block(P, Q, X, block_, (*words))
        (*words) += 16
    } else {
        gen_block_128_Q_block(Q, P, Y, block_, (*words) - 512)
        (*words) += 16
        if (*words) == 1024 {
            (*words) = 0
        }
    }
}

func generate_block_128(P, Q, X, Y []uint32, words *uint32) {
    if (*words) < 512 {
        gen_block_128_P(P, Q, X, (*words))
        (*words) += 16
    } else {
        gen_block_128_Q(Q, P, Y, (*words) - 512)
        (*words) += 16
        if (*words) == 1024 {
            (*words) = 0
        }
    }
}

