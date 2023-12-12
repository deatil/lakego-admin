package siphash

import (
    "math/bits"
)

const BLOCK_SIZE      =  8
const KEY_SIZE        = 16
const MIN_DIGEST_SIZE =  8
const MAX_DIGEST_SIZE = 16

const C_ROUNDS = 2
const D_ROUNDS = 4

func ROTL(x, n uint64) uint64 {
    return bits.RotateLeft64(x, int(n))
}

func U32TO8_LE(p []byte, v uint32) {
    p[0] = byte(v)
    p[1] = byte(v >> 8)
    p[2] = byte(v >> 16)
    p[3] = byte(v >> 24)
}

func U64TO8_LE(p []byte, v uint64) {
    U32TO8_LE(p, uint32(v))
    U32TO8_LE(p[4:], uint32(v >> 32))
}

func U8TO64_LE(p []byte) uint64 {
    v := (uint64(p[0])      ) |
         (uint64(p[1]) <<  8) |
         (uint64(p[2]) << 16) |
         (uint64(p[3]) << 24) |
         (uint64(p[4]) << 32) |
         (uint64(p[5]) << 40) |
         (uint64(p[6]) << 48) |
         (uint64(p[7]) << 56)

    return v
}

func SIPROUND(v0, v1, v2, v3 *uint64) {
    (*v0) += (*v1)
    (*v1) = ROTL((*v1), 13)

    (*v1) ^= (*v0)
    (*v0) = ROTL((*v0), 32)

    (*v2) += (*v3)
    (*v3) = ROTL((*v3), 16)

    (*v3) ^= (*v2)
    (*v0) += (*v3)
    (*v3) = ROTL((*v3), 21)

    (*v3) ^= (*v0)
    (*v2) += (*v1)
    (*v1) = ROTL((*v1), 17)

    (*v1) ^= (*v2)
    (*v2) = ROTL((*v2), 32)
}
