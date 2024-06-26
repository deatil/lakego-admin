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
    return x ^ ROTL(x, 9) ^ ROTL(x, 17)
}

func P1(x uint32) uint32 {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23)
}

func FF00(x, y, z uint32) uint32 {
    return x ^ y ^ z
}

func FF16(x, y, z uint32) uint32 {
    return (x & y) | (x & z) | (y & z)
}

func GG00(x, y, z uint32) uint32 {
    return x ^ y ^ z
}

func GG16(x, y, z uint32) uint32 {
    return ((y ^ z) & x) ^ z
}

func compressBlock(digest []uint32, data []byte) {
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
        SS1 = ROTL((ROTL(A, 12) + E + tSbox[j]), 7)
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
        SS1 = ROTL((ROTL(A, 12) + E + tSbox[j]), 7)
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
}

func GenT() []uint32 {
    init1 := 0x79CC4519
    init2 := 0x7A879D8A

    var T = make([]uint32, 0)
    for j := 0; j < 16; j++ {
        Tj := (init1 << uint32(j)) | (init1 >> (32 - uint32(j)))

        T = append(T, uint32(Tj))
    }

    for j := 16; j < 64; j++ {
        n := j % 32
        Tj := (init2 << uint32(n)) | (init2 >> (32 - uint32(n)))

        T = append(T, uint32(Tj))
    }

    // fmt.Printf("0x%08X, ", Tj)

    return T
}
