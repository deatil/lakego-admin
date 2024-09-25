package sm3

func blockGeneric(d *digest, data []byte) {
    var W [68]uint32
    var SS1, SS2, TT1, TT2 uint32

    var j int32

    A := d.s[0]
    B := d.s[1]
    C := d.s[2]
    D := d.s[3]
    E := d.s[4]
    F := d.s[5]
    G := d.s[6]
    H := d.s[7]

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

    d.s[0] ^= A
    d.s[1] ^= B
    d.s[2] ^= C
    d.s[3] ^= D
    d.s[4] ^= E
    d.s[5] ^= F
    d.s[6] ^= G
    d.s[7] ^= H
}
