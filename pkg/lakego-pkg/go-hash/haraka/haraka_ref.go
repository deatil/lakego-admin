package haraka

const nRounds = 5

func haraka256Ref(dst, src *[32]byte) {
    var state [8]uint32
    // operate LittleEndian to correspond to the round constant byte-order
    state[0] = GETU32(src[0:4])
    state[1] = GETU32(src[4:8])
    state[2] = GETU32(src[8:12])
    state[3] = GETU32(src[12:16])
    state[4] = GETU32(src[16:20])
    state[5] = GETU32(src[20:24])
    state[6] = GETU32(src[24:28])
    state[7] = GETU32(src[28:32])

    // AES and mix
    for i := 0; i < nRounds; i++ {
        aesRound(rc[16*i:16*i+4], state[0:4])
        aesRound(rc[16*i+4:16*i+8], state[4:8])
        aesRound(rc[16*i+8:16*i+12], state[0:4])
        aesRound(rc[16*i+12:16*i+16], state[4:8])
        mix256(&state)
    }

    // final XOR of input
    state[0] ^= GETU32(src[0:4])
    state[1] ^= GETU32(src[4:8])
    state[2] ^= GETU32(src[8:12])
    state[3] ^= GETU32(src[12:16])
    state[4] ^= GETU32(src[16:20])
    state[5] ^= GETU32(src[20:24])
    state[6] ^= GETU32(src[24:28])
    state[7] ^= GETU32(src[28:32])

    PUTU32(dst[0:4], state[0])
    PUTU32(dst[4:8], state[1])
    PUTU32(dst[8:12], state[2])
    PUTU32(dst[12:16], state[3])
    PUTU32(dst[16:20], state[4])
    PUTU32(dst[20:24], state[5])
    PUTU32(dst[24:28], state[6])
    PUTU32(dst[28:32], state[7])
}

func haraka512Ref(dst *[32]byte, src *[64]byte) {
    var state [16]uint32
    // operate LittleEndian to correspond to the round constant byte-order
    state[0] = GETU32(src[0:4])
    state[1] = GETU32(src[4:8])
    state[2] = GETU32(src[8:12])
    state[3] = GETU32(src[12:16])
    state[4] = GETU32(src[16:20])
    state[5] = GETU32(src[20:24])
    state[6] = GETU32(src[24:28])
    state[7] = GETU32(src[28:32])
    state[8] = GETU32(src[32:36])
    state[9] = GETU32(src[36:40])
    state[10] = GETU32(src[40:44])
    state[11] = GETU32(src[44:48])
    state[12] = GETU32(src[48:52])
    state[13] = GETU32(src[52:56])
    state[14] = GETU32(src[56:60])
    state[15] = GETU32(src[60:64])

    // AES and mix
    for i := 0; i < nRounds; i++ {
        aesRound(rc[32*i:32*i+4], state[0:4])
        aesRound(rc[32*i+4:32*i+8], state[4:8])
        aesRound(rc[32*i+8:32*i+12], state[8:12])
        aesRound(rc[32*i+12:32*i+16], state[12:16])
        aesRound(rc[32*i+16:32*i+20], state[0:4])
        aesRound(rc[32*i+20:32*i+24], state[4:8])
        aesRound(rc[32*i+24:32*i+28], state[8:12])
        aesRound(rc[32*i+28:32*i+32], state[12:16])
        mix512(&state)
    }
    // final XOR
    state[0] ^= GETU32(src[0:4])
    state[1] ^= GETU32(src[4:8])
    state[2] ^= GETU32(src[8:12])
    state[3] ^= GETU32(src[12:16])
    state[4] ^= GETU32(src[16:20])
    state[5] ^= GETU32(src[20:24])
    state[6] ^= GETU32(src[24:28])
    state[7] ^= GETU32(src[28:32])
    state[8] ^= GETU32(src[32:36])
    state[9] ^= GETU32(src[36:40])
    state[10] ^= GETU32(src[40:44])
    state[11] ^= GETU32(src[44:48])
    state[12] ^= GETU32(src[48:52])
    state[13] ^= GETU32(src[52:56])
    state[14] ^= GETU32(src[56:60])
    state[15] ^= GETU32(src[60:64])

    PUTU32(dst[0:4], state[2])
    PUTU32(dst[4:8], state[3])
    PUTU32(dst[8:12], state[6])
    PUTU32(dst[12:16], state[7])
    PUTU32(dst[16:20], state[8])
    PUTU32(dst[20:24], state[9])
    PUTU32(dst[24:28], state[12])
    PUTU32(dst[28:32], state[13])
}

// swapEndian
func swapEndian(c []uint32) []uint32 {
    return []uint32{c[3], c[2], c[1], c[0]}
}

// mix256 is the 256-bit mixing round function
func mix256(s *[8]uint32) {
    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7] =
        s[0], s[4], s[1], s[5], s[2], s[6], s[3], s[7]
}

// mix512 is the 512-bit mixing round function
func mix512(s *[16]uint32) {
    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15] =
    s[3], s[11], s[7], s[15], s[8], s[0], s[12], s[4],
    s[9], s[1], s[13], s[5], s[2], s[10], s[6], s[14]
}
