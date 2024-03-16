package square

import (
    "math/bits"
    "encoding/binary"
)

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

func bytesToUint32(inp []byte) (blk uint32) {
    if littleEndian {
        blk = binary.LittleEndian.Uint32(inp[0:])
    } else {
        blk = binary.BigEndian.Uint32(inp[0:])
    }

    return
}

func uint32ToBytes(blk uint32) [4]byte {
    var sav [4]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk)
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk)
    }

    return sav
}

const R = 8 /* number of rounds	  */

func ROTL(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func ROTR(x, n uint32) uint32 {
    return ROTL(x, 32 - n);
}

func GETB0(x uint32) byte {
    return byte(x >> 24)
}
func GETB1(x uint32) byte {
    return byte(x >> 16)
}
func GETB2(x uint32) byte {
    return byte(x >> 8)
}
func GETB3(x uint32) byte {
    return byte(x)
}

func PUTB0(x byte) uint32 {
    return uint32(x) << 24
}
func PUTB1(x byte) uint32 {
    return uint32(x) << 16
}
func PUTB2(x byte) uint32 {
    return uint32(x) << 8
}
func PUTB3(x byte) uint32 {
    return uint32(x)
}

func PSI_ROTL(x, s uint32) uint32 {
    return ROTL(x, s)
}

func PSI_ROTR(x, s uint32) uint32 {
    return ROTR(x, s)
}

func squareTransform(roundKey *[4]uint32) {
    roundKey[0] = phi[GETB0(roundKey[0])] ^
        PSI_ROTR(phi[GETB1(roundKey[0])],  8) ^
        PSI_ROTR(phi[GETB2(roundKey[0])], 16) ^
        PSI_ROTR(phi[GETB3(roundKey[0])], 24);
    roundKey[1] = phi[GETB0(roundKey[1])] ^
        PSI_ROTR(phi[GETB1(roundKey[1])],  8) ^
        PSI_ROTR(phi[GETB2(roundKey[1])], 16) ^
        PSI_ROTR(phi[GETB3(roundKey[1])], 24);
    roundKey[2] = phi[GETB0(roundKey[2])] ^
        PSI_ROTR(phi[GETB1(roundKey[2])],  8) ^
        PSI_ROTR(phi[GETB2(roundKey[2])], 16) ^
        PSI_ROTR(phi[GETB3(roundKey[2])], 24);
    roundKey[3] = phi[GETB0(roundKey[3])] ^
        PSI_ROTR(phi[GETB1(roundKey[3])],  8) ^
        PSI_ROTR(phi[GETB2(roundKey[3])], 16) ^
        PSI_ROTR(phi[GETB3(roundKey[3])], 24);
}

func squareGenerateRoundKeys(
    key [4]uint32,
    roundKeys_e *[R+1][4]uint32,
    roundKeys_d *[R+1][4]uint32,
) {
    var t int

    copy(roundKeys_e[0][:], key[:])

    for t = 1; t < R+1; t++ {
        /* apply the key evolution function: */
        roundKeys_e[t][0] = roundKeys_e[t-1][0] ^ PSI_ROTL(roundKeys_e[t-1][3], 8) ^ offset[t-1]
        roundKeys_d[R-t][0] = roundKeys_e[t][0]

        roundKeys_e[t][1] = roundKeys_e[t-1][1] ^ roundKeys_e[t][0]
        roundKeys_d[R-t][1] = roundKeys_e[t][1]

        roundKeys_e[t][2] = roundKeys_e[t-1][2] ^ roundKeys_e[t][1]
        roundKeys_d[R-t][2] = roundKeys_e[t][2]

        roundKeys_e[t][3] = roundKeys_e[t-1][3] ^ roundKeys_e[t][2]
        roundKeys_d[R-t][3] = roundKeys_e[t][3]

        /* apply the theta diffusion function: */
        squareTransform(&roundKeys_e[t-1])
    }

    copy(roundKeys_d[R][:], roundKeys_e[0][:])
}

func squareExpandKey(key [4]uint32, roundKeys_e *[R+1][4]uint32) {
    var t int

    copy(roundKeys_e[0][:], key[:])

    for t = 1; t < R+1; t++ {
        /* apply the key evolution function: */
        roundKeys_e[t][0] = roundKeys_e[t-1][0] ^ PSI_ROTL(roundKeys_e[t-1][3], 8) ^ offset[t-1]
        roundKeys_e[t][1] = roundKeys_e[t-1][1] ^ roundKeys_e[t][0]
        roundKeys_e[t][2] = roundKeys_e[t-1][2] ^ roundKeys_e[t][1]
        roundKeys_e[t][3] = roundKeys_e[t-1][3] ^ roundKeys_e[t][2]

        /* apply the theta diffusion function: */
        squareTransform(&roundKeys_e[t-1])
    }
}

func squareRound(text [4]uint32, temp *[4]uint32, T0, T1, T2, T3 [256]uint32, roundKey [4]uint32) {
    temp[0] = T0[GETB0(text[0])] ^
            T1[GETB0(text[1])] ^
            T2[GETB0(text[2])] ^
            T3[GETB0(text[3])] ^
            roundKey[0];
    temp[1] = T0[GETB1(text[0])] ^
            T1[GETB1(text[1])] ^
            T2[GETB1(text[2])] ^
            T3[GETB1(text[3])] ^
            roundKey[1];
    temp[2] = T0[GETB2(text[0])] ^
            T1[GETB2(text[1])] ^
            T2[GETB2(text[2])] ^
            T3[GETB2(text[3])] ^
            roundKey[2];
    temp[3] = T0[GETB3(text[0])] ^
            T1[GETB3(text[1])] ^
            T2[GETB3(text[2])] ^
            T3[GETB3(text[3])] ^
            roundKey[3];
}

func squareFinal(text *[4]uint32, temp [4]uint32, S [256]byte, roundKey [4]uint32) {
    text[0] = PUTB0(S[GETB0(temp[0])]) ^
            PUTB1(S[GETB0(temp[1])]) ^
            PUTB2(S[GETB0(temp[2])]) ^
            PUTB3(S[GETB0(temp[3])]) ^
            roundKey[0];
    text[1] = PUTB0(S[GETB1(temp[0])]) ^
            PUTB1(S[GETB1(temp[1])]) ^
            PUTB2(S[GETB1(temp[2])]) ^
            PUTB3(S[GETB1(temp[3])]) ^
            roundKey[1];
    text[2] = PUTB0(S[GETB2(temp[0])]) ^
            PUTB1(S[GETB2(temp[1])]) ^
            PUTB2(S[GETB2(temp[2])]) ^
            PUTB3(S[GETB2(temp[3])]) ^
            roundKey[2];
    text[3] = PUTB0(S[GETB3(temp[0])]) ^
            PUTB1(S[GETB3(temp[1])]) ^
            PUTB2(S[GETB3(temp[2])]) ^
            PUTB3(S[GETB3(temp[3])]) ^
            roundKey[3];
}

func squareEncrypt(text *[4]uint32, roundKeys [R+1][4]uint32) {
    var temp [4]uint32

    /* initial key addition */
    text[0] ^= roundKeys[0][0]
    text[1] ^= roundKeys[0][1]
    text[2] ^= roundKeys[0][2]
    text[3] ^= roundKeys[0][3]

    /* R - 1 full rounds */
    squareRound(*text, &temp, Te0, Te1, Te2, Te3, roundKeys[1])
    squareRound(temp, text, Te0, Te1, Te2, Te3, roundKeys[2])
    squareRound(*text, &temp, Te0, Te1, Te2, Te3, roundKeys[3])
    squareRound(temp, text, Te0, Te1, Te2, Te3, roundKeys[4])
    squareRound(*text, &temp, Te0, Te1, Te2, Te3, roundKeys[5])
    squareRound(temp, text, Te0, Te1, Te2, Te3, roundKeys[6])
    squareRound(*text, &temp, Te0, Te1, Te2, Te3, roundKeys[7])

    /* last round(diffusion becomes only transposition) */
    squareFinal(text, temp, Se, roundKeys[R])
}

func squareDecrypt(text *[4]uint32, roundKeys [R+1][4]uint32) {
    var temp [4]uint32

    /* initial key addition */
    text[0] ^= roundKeys[0][0]
    text[1] ^= roundKeys[0][1]
    text[2] ^= roundKeys[0][2]
    text[3] ^= roundKeys[0][3]

    /* R - 1 full rounds */
    squareRound(*text, &temp, Td0, Td1, Td2, Td3, roundKeys[1])
    squareRound(temp, text, Td0, Td1, Td2, Td3, roundKeys[2])
    squareRound(*text, &temp, Td0, Td1, Td2, Td3, roundKeys[3])
    squareRound(temp, text, Td0, Td1, Td2, Td3, roundKeys[4])
    squareRound(*text, &temp, Td0, Td1, Td2, Td3, roundKeys[5])
    squareRound(temp, text, Td0, Td1, Td2, Td3, roundKeys[6])
    squareRound(*text, &temp, Td0, Td1, Td2, Td3, roundKeys[7])

    /* last round(diffusion becomes only transposition) */
    squareFinal(text, temp, Sd, roundKeys[R])
}

