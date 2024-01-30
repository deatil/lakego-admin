package sm3

import (
    "math/bits"
    "encoding/binary"
)

func GETU32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func PUTU32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
}

func ROTL(x uint32, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func P0(x uint32) uint32 {
    return (x ^ ROTL(x, 9) ^ ROTL(x, 17))
}

func P1(x uint32) uint32 {
    return (x ^ ROTL(x, 15) ^ ROTL(x, 23))
}

func FF00(x, y, z uint32) uint32 {
    return (x ^ y ^ z)
}

func FF16(x, y, z uint32) uint32 {
    return ((x & y) | (x & z) | (y & z))
}

func GG00(x, y, z uint32) uint32 {
    return (x ^ y ^ z)
}

func GG16(x, y, z uint32) uint32 {
    return (((y ^ z) & x) ^ z)
}

func memsetUint8(a []uint8, v uint8) {
    if len(a) == 0 {
        return
    }

    a[0] = v
    for bp := 1; bp < len(a); bp *= 2 {
        copy(a[bp:], a[:bp])
    }
}

var keys = [64]uint32{
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
    0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
    0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
    0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
    0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53,
    0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
    0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4,
    0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
    0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
    0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
}

func compressBlocks(digest []uint32, data []uint8, blocks int) {
    var A uint32
    var B uint32
    var C uint32
    var D uint32
    var E uint32
    var F uint32
    var G uint32
    var H uint32
    var W [68]uint32
    var SS1, SS2, TT1, TT2 uint32

    var j int32

    for ; blocks > 0; blocks-- {

        A = digest[0]
        B = digest[1]
        C = digest[2]
        D = digest[3]
        E = digest[4]
        F = digest[5]
        G = digest[6]
        H = digest[7]

        for j = 0; j < 16; j++ {
            W[j] = GETU32(data[j*4:])
        }

        for ; j < 68; j++ {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^
                   ROTL(W[j - 13], 7) ^ W[j - 6]
        }

        for j = 0; j < 16; j++ {
            SS1 = ROTL((ROTL(A, 12) + E + keys[j]), 7)
            SS2 = SS1 ^ ROTL(A, 12)

            TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j + 4])
            TT2 = GG00(E, F, G) + H + SS1 + W[j]

            D = C
            C = ROTL(B, 9)
            B = A
            A = TT1
            H = G
            G = ROTL(F, 19)
            F = E
            E = P0(TT2)
        }

        for ; j < 64; j++ {
            SS1 = ROTL((ROTL(A, 12) + E + keys[j]), 7)
            SS2 = SS1 ^ ROTL(A, 12)

            TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j + 4])
            TT2 = GG16(E, F, G) + H + SS1 + W[j]

            D = C
            C = ROTL(B, 9)
            B = A
            A = TT1
            H = G
            G = ROTL(F, 19)
            F = E
            E = P0(TT2)
        }

        digest[0] ^= A
        digest[1] ^= B
        digest[2] ^= C
        digest[3] ^= D
        digest[4] ^= E
        digest[5] ^= F
        digest[6] ^= G
        digest[7] ^= H

        data = data[64:]
    }
}
