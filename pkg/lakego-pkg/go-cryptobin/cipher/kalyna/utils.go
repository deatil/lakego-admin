package kalyna

import (
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func keyToUint64s(b []byte) []uint64 {
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

// ========

func G0(x []uint64, y []uint64) {
    y[0] = KUPYNA_T[0][byte(x[0])] ^
        KUPYNA_T[1][byte(x[7] >> 8)] ^
        KUPYNA_T[2][byte(x[6] >> 16)] ^
        KUPYNA_T[3][byte(x[5] >> 24)] ^
        KUPYNA_T[4][byte(x[4] >> 32)] ^
        KUPYNA_T[5][byte(x[3] >> 40)] ^
        KUPYNA_T[6][byte(x[2] >> 48)] ^
        KUPYNA_T[7][byte(x[1] >> 56)]
    y[1] = KUPYNA_T[0][byte(x[1])] ^
        KUPYNA_T[1][byte(x[0] >> 8)] ^
        KUPYNA_T[2][byte(x[7] >> 16)] ^
        KUPYNA_T[3][byte(x[6] >> 24)] ^
        KUPYNA_T[4][byte(x[5] >> 32)] ^
        KUPYNA_T[5][byte(x[4] >> 40)] ^
        KUPYNA_T[6][byte(x[3] >> 48)] ^
        KUPYNA_T[7][byte(x[2] >> 56)]
    y[2] = KUPYNA_T[0][byte(x[2])] ^
        KUPYNA_T[1][byte(x[1] >> 8)] ^
        KUPYNA_T[2][byte(x[0] >> 16)] ^
        KUPYNA_T[3][byte(x[7] >> 24)] ^
        KUPYNA_T[4][byte(x[6] >> 32)] ^
        KUPYNA_T[5][byte(x[5] >> 40)] ^
        KUPYNA_T[6][byte(x[4] >> 48)] ^
        KUPYNA_T[7][byte(x[3] >> 56)]
    y[3] = KUPYNA_T[0][byte(x[3])] ^
        KUPYNA_T[1][byte(x[2] >> 8)] ^
        KUPYNA_T[2][byte(x[1] >> 16)] ^
        KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[7] >> 32)] ^
        KUPYNA_T[5][byte(x[6] >> 40)] ^
        KUPYNA_T[6][byte(x[5] >> 48)] ^
        KUPYNA_T[7][byte(x[4] >> 56)]
    y[4] = KUPYNA_T[0][byte(x[4])] ^
        KUPYNA_T[1][byte(x[3] >> 8)] ^
        KUPYNA_T[2][byte(x[2] >> 16)] ^
        KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^
        KUPYNA_T[5][byte(x[7] >> 40)] ^
        KUPYNA_T[6][byte(x[6] >> 48)] ^
        KUPYNA_T[7][byte(x[5] >> 56)]
    y[5] = KUPYNA_T[0][byte(x[5])] ^
        KUPYNA_T[1][byte(x[4] >> 8)] ^
        KUPYNA_T[2][byte(x[3] >> 16)] ^
        KUPYNA_T[3][byte(x[2] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^
        KUPYNA_T[5][byte(x[0] >> 40)] ^
        KUPYNA_T[6][byte(x[7] >> 48)] ^
        KUPYNA_T[7][byte(x[6] >> 56)]
    y[6] = KUPYNA_T[0][byte(x[6])] ^
        KUPYNA_T[1][byte(x[5] >> 8)] ^
        KUPYNA_T[2][byte(x[4] >> 16)] ^
        KUPYNA_T[3][byte(x[3] >> 24)] ^
        KUPYNA_T[4][byte(x[2] >> 32)] ^
        KUPYNA_T[5][byte(x[1] >> 40)] ^
        KUPYNA_T[6][byte(x[0] >> 48)] ^
        KUPYNA_T[7][byte(x[7] >> 56)]
    y[7] = KUPYNA_T[0][byte(x[7])] ^
        KUPYNA_T[1][byte(x[6] >> 8)] ^
        KUPYNA_T[2][byte(x[5] >> 16)] ^
        KUPYNA_T[3][byte(x[4] >> 24)] ^
        KUPYNA_T[4][byte(x[3] >> 32)] ^
        KUPYNA_T[5][byte(x[2] >> 40)] ^
        KUPYNA_T[6][byte(x[1] >> 48)] ^
        KUPYNA_T[7][byte(x[0] >> 56)]
}

func G(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] ^ KUPYNA_T[0][byte(x[0])] ^
        KUPYNA_T[1][byte(x[7] >> 8)] ^
        KUPYNA_T[2][byte(x[6] >> 16)] ^
        KUPYNA_T[3][byte(x[5] >> 24)] ^
        KUPYNA_T[4][byte(x[4] >> 32)] ^
        KUPYNA_T[5][byte(x[3] >> 40)] ^
        KUPYNA_T[6][byte(x[2] >> 48)] ^
        KUPYNA_T[7][byte(x[1] >> 56)]
    y[1] = k[1] ^ KUPYNA_T[0][byte(x[1])] ^
        KUPYNA_T[1][byte(x[0] >> 8)] ^
        KUPYNA_T[2][byte(x[7] >> 16)] ^
        KUPYNA_T[3][byte(x[6] >> 24)] ^
        KUPYNA_T[4][byte(x[5] >> 32)] ^
        KUPYNA_T[5][byte(x[4] >> 40)] ^
        KUPYNA_T[6][byte(x[3] >> 48)] ^
        KUPYNA_T[7][byte(x[2] >> 56)]
    y[2] = k[2] ^ KUPYNA_T[0][byte(x[2])] ^
        KUPYNA_T[1][byte(x[1] >> 8)] ^
        KUPYNA_T[2][byte(x[0] >> 16)] ^
        KUPYNA_T[3][byte(x[7] >> 24)] ^
        KUPYNA_T[4][byte(x[6] >> 32)] ^
        KUPYNA_T[5][byte(x[5] >> 40)] ^
        KUPYNA_T[6][byte(x[4] >> 48)] ^
        KUPYNA_T[7][byte(x[3] >> 56)]
    y[3] = k[3] ^ KUPYNA_T[0][byte(x[3])] ^
        KUPYNA_T[1][byte(x[2] >> 8)] ^
        KUPYNA_T[2][byte(x[1] >> 16)] ^
        KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[7] >> 32)] ^
        KUPYNA_T[5][byte(x[6] >> 40)] ^
        KUPYNA_T[6][byte(x[5] >> 48)] ^
        KUPYNA_T[7][byte(x[4] >> 56)]
    y[4] = k[4] ^ KUPYNA_T[0][byte(x[4])] ^
        KUPYNA_T[1][byte(x[3] >> 8)] ^
        KUPYNA_T[2][byte(x[2] >> 16)] ^
        KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^
        KUPYNA_T[5][byte(x[7] >> 40)] ^
        KUPYNA_T[6][byte(x[6] >> 48)] ^
        KUPYNA_T[7][byte(x[5] >> 56)]
    y[5] = k[5] ^ KUPYNA_T[0][byte(x[5])] ^
        KUPYNA_T[1][byte(x[4] >> 8)] ^
        KUPYNA_T[2][byte(x[3] >> 16)] ^
        KUPYNA_T[3][byte(x[2] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^
        KUPYNA_T[5][byte(x[0] >> 40)] ^
        KUPYNA_T[6][byte(x[7] >> 48)] ^
        KUPYNA_T[7][byte(x[6] >> 56)];
    y[6] = k[6] ^ KUPYNA_T[0][byte(x[6])] ^
        KUPYNA_T[1][byte(x[5] >> 8)] ^
        KUPYNA_T[2][byte(x[4] >> 16)] ^
        KUPYNA_T[3][byte(x[3] >> 24)] ^
        KUPYNA_T[4][byte(x[2] >> 32)] ^
        KUPYNA_T[5][byte(x[1] >> 40)] ^
        KUPYNA_T[6][byte(x[0] >> 48)] ^
        KUPYNA_T[7][byte(x[7] >> 56)]
    y[7] = k[7] ^ KUPYNA_T[0][byte(x[7])] ^
        KUPYNA_T[1][byte(x[6] >> 8)] ^
        KUPYNA_T[2][byte(x[5] >> 16)] ^
        KUPYNA_T[3][byte(x[4] >> 24)] ^
        KUPYNA_T[4][byte(x[3] >> 32)] ^
        KUPYNA_T[5][byte(x[2] >> 40)] ^
        KUPYNA_T[6][byte(x[1] >> 48)] ^
        KUPYNA_T[7][byte(x[0] >> 56)]
}

func GL(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] + (KUPYNA_T[0][byte(x[0])] ^
        KUPYNA_T[1][byte(x[7] >> 8)] ^
        KUPYNA_T[2][byte(x[6] >> 16)] ^
        KUPYNA_T[3][byte(x[5] >> 24)] ^
        KUPYNA_T[4][byte(x[4] >> 32)] ^
        KUPYNA_T[5][byte(x[3] >> 40)] ^
        KUPYNA_T[6][byte(x[2] >> 48)] ^
        KUPYNA_T[7][byte(x[1] >> 56)])
    y[1] = k[1] + (KUPYNA_T[0][byte(x[1])] ^
        KUPYNA_T[1][byte(x[0] >> 8)] ^
        KUPYNA_T[2][byte(x[7] >> 16)] ^
        KUPYNA_T[3][byte(x[6] >> 24)] ^
        KUPYNA_T[4][byte(x[5] >> 32)] ^
        KUPYNA_T[5][byte(x[4] >> 40)] ^
        KUPYNA_T[6][byte(x[3] >> 48)] ^
        KUPYNA_T[7][byte(x[2] >> 56)])
    y[2] = k[2] + (KUPYNA_T[0][byte(x[2])] ^
        KUPYNA_T[1][byte(x[1] >> 8)] ^
        KUPYNA_T[2][byte(x[0] >> 16)] ^
        KUPYNA_T[3][byte(x[7] >> 24)] ^
        KUPYNA_T[4][byte(x[6] >> 32)] ^
        KUPYNA_T[5][byte(x[5] >> 40)] ^
        KUPYNA_T[6][byte(x[4] >> 48)] ^
        KUPYNA_T[7][byte(x[3] >> 56)])
    y[3] = k[3] + (KUPYNA_T[0][byte(x[3])] ^
        KUPYNA_T[1][byte(x[2] >> 8)] ^
        KUPYNA_T[2][byte(x[1] >> 16)] ^
        KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[7] >> 32)] ^
        KUPYNA_T[5][byte(x[6] >> 40)] ^
        KUPYNA_T[6][byte(x[5] >> 48)] ^
        KUPYNA_T[7][byte(x[4] >> 56)])
    y[4] = k[4] + (KUPYNA_T[0][byte(x[4])] ^
        KUPYNA_T[1][byte(x[3] >> 8)] ^
        KUPYNA_T[2][byte(x[2] >> 16)] ^
        KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^
        KUPYNA_T[5][byte(x[7] >> 40)] ^
        KUPYNA_T[6][byte(x[6] >> 48)] ^
        KUPYNA_T[7][byte(x[5] >> 56)])
    y[5] = k[5] + (KUPYNA_T[0][byte(x[5])] ^
        KUPYNA_T[1][byte(x[4] >> 8)] ^
        KUPYNA_T[2][byte(x[3] >> 16)] ^
        KUPYNA_T[3][byte(x[2] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^
        KUPYNA_T[5][byte(x[0] >> 40)] ^
        KUPYNA_T[6][byte(x[7] >> 48)] ^
        KUPYNA_T[7][byte(x[6] >> 56)])
    y[6] = k[6] + (KUPYNA_T[0][byte(x[6])] ^
        KUPYNA_T[1][byte(x[5] >> 8)] ^
        KUPYNA_T[2][byte(x[4] >> 16)] ^
        KUPYNA_T[3][byte(x[3] >> 24)] ^
        KUPYNA_T[4][byte(x[2] >> 32)] ^
        KUPYNA_T[5][byte(x[1] >> 40)] ^
        KUPYNA_T[6][byte(x[0] >> 48)] ^
        KUPYNA_T[7][byte(x[7] >> 56)])
    y[7] = k[7] + (KUPYNA_T[0][byte(x[7])] ^
        KUPYNA_T[1][byte(x[6] >> 8)] ^
        KUPYNA_T[2][byte(x[5] >> 16)] ^
        KUPYNA_T[3][byte(x[4] >> 24)] ^
        KUPYNA_T[4][byte(x[3] >> 32)] ^
        KUPYNA_T[5][byte(x[2] >> 40)] ^
        KUPYNA_T[6][byte(x[1] >> 48)] ^
        KUPYNA_T[7][byte(x[0] >> 56)])
}

func IMC(x []uint64) {
    x[0] = IT[0][S[0][byte(x[0])]] ^
        IT[1][S[1][byte(x[0] >> 8)]] ^
        IT[2][S[2][byte(x[0] >> 16)]] ^
        IT[3][S[3][byte(x[0] >> 24)]] ^
        IT[4][S[0][byte(x[0] >> 32)]] ^
        IT[5][S[1][byte(x[0] >> 40)]] ^
        IT[6][S[2][byte(x[0] >> 48)]] ^
        IT[7][S[3][byte(x[0] >> 56)]]
    x[1] = IT[0][S[0][byte(x[1])]] ^
        IT[1][S[1][byte(x[1] >> 8)]] ^
        IT[2][S[2][byte(x[1] >> 16)]] ^
        IT[3][S[3][byte(x[1] >> 24)]] ^
        IT[4][S[0][byte(x[1] >> 32)]] ^
        IT[5][S[1][byte(x[1] >> 40)]] ^
        IT[6][S[2][byte(x[1] >> 48)]] ^
        IT[7][S[3][byte(x[1] >> 56)]]
    x[2] = IT[0][S[0][byte(x[2])]] ^
        IT[1][S[1][byte(x[2] >> 8)]] ^
        IT[2][S[2][byte(x[2] >> 16)]] ^
        IT[3][S[3][byte(x[2] >> 24)]] ^
        IT[4][S[0][byte(x[2] >> 32)]] ^
        IT[5][S[1][byte(x[2] >> 40)]] ^
        IT[6][S[2][byte(x[2] >> 48)]] ^
        IT[7][S[3][byte(x[2] >> 56)]]
    x[3] = IT[0][S[0][byte(x[3])]] ^
        IT[1][S[1][byte(x[3] >> 8)]] ^
        IT[2][S[2][byte(x[3] >> 16)]] ^
        IT[3][S[3][byte(x[3] >> 24)]] ^
        IT[4][S[0][byte(x[3] >> 32)]] ^
        IT[5][S[1][byte(x[3] >> 40)]] ^
        IT[6][S[2][byte(x[3] >> 48)]] ^
        IT[7][S[3][byte(x[3] >> 56)]]
    x[4] = IT[0][S[0][byte(x[4])]] ^
        IT[1][S[1][byte(x[4] >> 8)]] ^
        IT[2][S[2][byte(x[4] >> 16)]] ^
        IT[3][S[3][byte(x[4] >> 24)]] ^
        IT[4][S[0][byte(x[4] >> 32)]] ^
        IT[5][S[1][byte(x[4] >> 40)]] ^
        IT[6][S[2][byte(x[4] >> 48)]] ^
        IT[7][S[3][byte(x[4] >> 56)]]
    x[5] = IT[0][S[0][byte(x[5])]] ^
        IT[1][S[1][byte(x[5] >> 8)]] ^
        IT[2][S[2][byte(x[5] >> 16)]] ^
        IT[3][S[3][byte(x[5] >> 24)]] ^
        IT[4][S[0][byte(x[5] >> 32)]] ^
        IT[5][S[1][byte(x[5] >> 40)]] ^
        IT[6][S[2][byte(x[5] >> 48)]] ^
        IT[7][S[3][byte(x[5] >> 56)]]
    x[6] = IT[0][S[0][byte(x[6])]] ^
        IT[1][S[1][byte(x[6] >> 8)]] ^
        IT[2][S[2][byte(x[6] >> 16)]] ^
        IT[3][S[3][byte(x[6] >> 24)]] ^
        IT[4][S[0][byte(x[6] >> 32)]] ^
        IT[5][S[1][byte(x[6] >> 40)]] ^
        IT[6][S[2][byte(x[6] >> 48)]] ^
        IT[7][S[3][byte(x[6] >> 56)]];
    x[7] = IT[0][S[0][byte(x[7])]] ^
        IT[1][S[1][byte(x[7] >> 8)]] ^
        IT[2][S[2][byte(x[7] >> 16)]] ^
        IT[3][S[3][byte(x[7] >> 24)]] ^
        IT[4][S[0][byte(x[7] >> 32)]] ^
        IT[5][S[1][byte(x[7] >> 40)]] ^
        IT[6][S[2][byte(x[7] >> 48)]] ^
        IT[7][S[3][byte(x[7] >> 56)]]
}

func IG(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] ^ IT[0][byte(x[0])] ^
        IT[1][byte(x[1] >> 8)] ^
        IT[2][byte(x[2] >> 16)] ^
        IT[3][byte(x[3] >> 24)] ^
        IT[4][byte(x[4] >> 32)] ^
        IT[5][byte(x[5] >> 40)] ^
        IT[6][byte(x[6] >> 48)] ^
        IT[7][byte(x[7] >> 56)]
    y[1] = k[1] ^ IT[0][byte(x[1])] ^
        IT[1][byte(x[2] >> 8)] ^
        IT[2][byte(x[3] >> 16)] ^
        IT[3][byte(x[4] >> 24)] ^
        IT[4][byte(x[5] >> 32)] ^
        IT[5][byte(x[6] >> 40)] ^
        IT[6][byte(x[7] >> 48)] ^
        IT[7][byte(x[0] >> 56)]
    y[2] = k[2] ^ IT[0][byte(x[2])] ^
        IT[1][byte(x[3] >> 8)] ^
        IT[2][byte(x[4] >> 16)] ^
        IT[3][byte(x[5] >> 24)] ^
        IT[4][byte(x[6] >> 32)] ^
        IT[5][byte(x[7] >> 40)] ^
        IT[6][byte(x[0] >> 48)] ^
        IT[7][byte(x[1] >> 56)]
    y[3] = k[3] ^ IT[0][byte(x[3])] ^
        IT[1][byte(x[4] >> 8)] ^
        IT[2][byte(x[5] >> 16)] ^
        IT[3][byte(x[6] >> 24)] ^
        IT[4][byte(x[7] >> 32)] ^
        IT[5][byte(x[0] >> 40)] ^
        IT[6][byte(x[1] >> 48)] ^
        IT[7][byte(x[2] >> 56)]
    y[4] = k[4] ^ IT[0][byte(x[4])] ^
        IT[1][byte(x[5] >> 8)] ^
        IT[2][byte(x[6] >> 16)] ^
        IT[3][byte(x[7] >> 24)] ^
        IT[4][byte(x[0] >> 32)] ^
        IT[5][byte(x[1] >> 40)] ^
        IT[6][byte(x[2] >> 48)] ^
        IT[7][byte(x[3] >> 56)]
    y[5] = k[5] ^ IT[0][byte(x[5])] ^
        IT[1][byte(x[6] >> 8)] ^
        IT[2][byte(x[7] >> 16)] ^
        IT[3][byte(x[0] >> 24)] ^
        IT[4][byte(x[1] >> 32)] ^
        IT[5][byte(x[2] >> 40)] ^
        IT[6][byte(x[3] >> 48)] ^
        IT[7][byte(x[4] >> 56)]
    y[6] = k[6] ^ IT[0][byte(x[6])] ^
        IT[1][byte(x[7] >> 8)] ^
        IT[2][byte(x[0] >> 16)] ^
        IT[3][byte(x[1] >> 24)] ^
        IT[4][byte(x[2] >> 32)] ^
        IT[5][byte(x[3] >> 40)] ^
        IT[6][byte(x[4] >> 48)] ^
        IT[7][byte(x[5] >> 56)]
    y[7] = k[7] ^ IT[0][byte(x[7])] ^
        IT[1][byte(x[0] >> 8)] ^
        IT[2][byte(x[1] >> 16)] ^
        IT[3][byte(x[2] >> 24)] ^
        IT[4][byte(x[3] >> 32)] ^
        IT[5][byte(x[4] >> 40)] ^
        IT[6][byte(x[5] >> 48)] ^
        IT[7][byte(x[6] >> 56)]
}

func IGL(x []uint64, y []uint64, k []uint64) {
    y[0] = (uint64(IS[0][byte(x[0])]) ^
        uint64(IS[1][byte(x[1] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[2] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[3] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[4] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[5] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[6] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[7] >> 56)]) << 56) - k[0]
    y[1] = (uint64(IS[0][byte(x[1])]) ^
        uint64(IS[1][byte(x[2] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[3] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[4] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[5] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[6] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[7] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[0] >> 56)]) << 56) - k[1]
    y[2] = (uint64(IS[0][byte(x[2])]) ^
        uint64(IS[1][byte(x[3] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[4] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[5] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[6] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[7] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[0] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[1] >> 56)]) << 56) - k[2]
    y[3] = (uint64(IS[0][byte(x[3])]) ^
        uint64(IS[1][byte(x[4] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[5] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[6] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[7] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[0] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[1] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[2] >> 56)]) << 56) - k[3]
    y[4] = (uint64(IS[0][byte(x[4])]) ^
        uint64(IS[1][byte(x[5] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[6] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[7] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[0] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[1] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[2] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[3] >> 56)]) << 56) - k[4]
    y[5] = (uint64(IS[0][byte(x[5])]) ^
        uint64(IS[1][byte(x[6] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[7] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[0] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[1] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[2] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[3] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[4] >> 56)]) << 56) - k[5]
    y[6] = (uint64(IS[0][byte(x[6])]) ^
        uint64(IS[1][byte(x[7] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[0] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[1] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[2] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[3] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[4] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[5] >> 56)]) << 56) - k[6]
    y[7] = (uint64(IS[0][byte(x[7])]) ^
        uint64(IS[1][byte(x[0] >> 8)]) << 8 ^
        uint64(IS[2][byte(x[1] >> 16)]) << 16 ^
        uint64(IS[3][byte(x[2] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[3] >> 32)]) << 32 ^
        uint64(IS[1][byte(x[4] >> 40)]) << 40 ^
        uint64(IS[2][byte(x[5] >> 48)]) << 48 ^
        uint64(IS[3][byte(x[6] >> 56)]) << 56) - k[7]
}

func addkey(x []uint64, y []uint64, k []uint64) {
    y[0] = x[0] + k[0]
    y[1] = x[1] + k[1]
    y[2] = x[2] + k[2]
    y[3] = x[3] + k[3]
    y[4] = x[4] + k[4]
    y[5] = x[5] + k[5]
    y[6] = x[6] + k[6]
    y[7] = x[7] + k[7]
}

func subkey(x []uint64, y []uint64, k []uint64) {
    y[0] = x[0] - k[0]
    y[1] = x[1] - k[1]
    y[2] = x[2] - k[2]
    y[3] = x[3] - k[3]
    y[4] = x[4] - k[4]
    y[5] = x[5] - k[5]
    y[6] = x[6] - k[6]
    y[7] = x[7] - k[7]
}

func swap_block(k []uint64) {
    t := k[0]
    k[0] = k[1]
    k[1] = k[2]
    k[2] = k[3]
    k[3] = k[4]
    k[4] = k[5]
    k[5] = k[6]
    k[6] = k[7]
    k[7] = t
}

func add_constant(src []uint64, dst []uint64, constant uint64) {
    var i int
    for i = 0; i < 8; i++ {
        dst[i] = src[i] + constant
    }
}

func make_odd_key(evenkey []uint64, oddkey []uint64) {
    evenkeys := uint64sToBytes(evenkey)
    oddkeys := uint64sToBytes(oddkey)

    copy(oddkeys, evenkeys[19:64])
    copy(oddkeys[64-19:], evenkeys[:19])

    res := keyToUint64s(oddkeys)
    copy(oddkey, res)
}

// ==================

func addkey256(x, y, k []uint64) {
    y[0] = x[0] + k[0]
    y[1] = x[1] + k[1]
    y[2] = x[2] + k[2]
    y[3] = x[3] + k[3]
}

func subkey256(x, y, k []uint64) {
    y[0] = x[0] - k[0]
    y[1] = x[1] - k[1]
    y[2] = x[2] - k[2]
    y[3] = x[3] - k[3]
}

func G0256(x []uint64, y []uint64) {
    y[0] = KUPYNA_T[0][byte(x[0])] ^ KUPYNA_T[1][byte(x[0] >> 8)] ^ KUPYNA_T[2][byte(x[3] >> 16)] ^ KUPYNA_T[3][byte(x[3] >> 24)] ^
        KUPYNA_T[4][byte(x[2] >> 32)] ^ KUPYNA_T[5][byte(x[2] >> 40)] ^ KUPYNA_T[6][byte(x[1] >> 48)] ^ KUPYNA_T[7][byte(x[1] >> 56)]
    y[1] = KUPYNA_T[0][byte(x[1])] ^ KUPYNA_T[1][byte(x[1] >> 8)] ^ KUPYNA_T[2][byte(x[0] >> 16)] ^ KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[3] >> 32)] ^ KUPYNA_T[5][byte(x[3] >> 40)] ^ KUPYNA_T[6][byte(x[2] >> 48)] ^ KUPYNA_T[7][byte(x[2] >> 56)]
    y[2] = KUPYNA_T[0][byte(x[2])] ^ KUPYNA_T[1][byte(x[2] >> 8)] ^ KUPYNA_T[2][byte(x[1] >> 16)] ^ KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^ KUPYNA_T[5][byte(x[0] >> 40)] ^ KUPYNA_T[6][byte(x[3] >> 48)] ^ KUPYNA_T[7][byte(x[3] >> 56)]
    y[3] = KUPYNA_T[0][byte(x[3])] ^ KUPYNA_T[1][byte(x[3] >> 8)] ^ KUPYNA_T[2][byte(x[2] >> 16)] ^ KUPYNA_T[3][byte(x[2] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^ KUPYNA_T[5][byte(x[1] >> 40)] ^ KUPYNA_T[6][byte(x[0] >> 48)] ^ KUPYNA_T[7][byte(x[0] >> 56)]
}

func G256(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] ^ KUPYNA_T[0][byte(x[0])] ^ KUPYNA_T[1][byte(x[0] >> 8)] ^ KUPYNA_T[2][byte(x[3] >> 16)] ^ KUPYNA_T[3][byte(x[3] >> 24)] ^
        KUPYNA_T[4][byte(x[2] >> 32)] ^ KUPYNA_T[5][byte(x[2] >> 40)] ^ KUPYNA_T[6][byte(x[1] >> 48)] ^ KUPYNA_T[7][byte(x[1] >> 56)]
    y[1] = k[1] ^ KUPYNA_T[0][byte(x[1])] ^ KUPYNA_T[1][byte(x[1] >> 8)] ^ KUPYNA_T[2][byte(x[0] >> 16)] ^ KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[3] >> 32)] ^ KUPYNA_T[5][byte(x[3] >> 40)] ^ KUPYNA_T[6][byte(x[2] >> 48)] ^ KUPYNA_T[7][byte(x[2] >> 56)]
    y[2] = k[2] ^ KUPYNA_T[0][byte(x[2])] ^ KUPYNA_T[1][byte(x[2] >> 8)] ^ KUPYNA_T[2][byte(x[1] >> 16)] ^ KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^ KUPYNA_T[5][byte(x[0] >> 40)] ^ KUPYNA_T[6][byte(x[3] >> 48)] ^ KUPYNA_T[7][byte(x[3] >> 56)]
    y[3] = k[3] ^ KUPYNA_T[0][byte(x[3])] ^ KUPYNA_T[1][byte(x[3] >> 8)] ^ KUPYNA_T[2][byte(x[2] >> 16)] ^ KUPYNA_T[3][byte(x[2] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^ KUPYNA_T[5][byte(x[1] >> 40)] ^ KUPYNA_T[6][byte(x[0] >> 48)] ^ KUPYNA_T[7][byte(x[0] >> 56)]
}

func GL256(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] + (KUPYNA_T[0][byte(x[0])] ^ KUPYNA_T[1][byte(x[0] >> 8)] ^ KUPYNA_T[2][byte(x[3] >> 16)] ^ KUPYNA_T[3][byte(x[3] >> 24)] ^
        KUPYNA_T[4][byte(x[2] >> 32)] ^ KUPYNA_T[5][byte(x[2] >> 40)] ^ KUPYNA_T[6][byte(x[1] >> 48)] ^ KUPYNA_T[7][byte(x[1] >> 56)])
    y[1] = k[1] + (KUPYNA_T[0][byte(x[1])] ^ KUPYNA_T[1][byte(x[1] >> 8)] ^ KUPYNA_T[2][byte(x[0] >> 16)] ^ KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[3] >> 32)] ^ KUPYNA_T[5][byte(x[3] >> 40)] ^ KUPYNA_T[6][byte(x[2] >> 48)] ^ KUPYNA_T[7][byte(x[2] >> 56)])
    y[2] = k[2] + (KUPYNA_T[0][byte(x[2])] ^ KUPYNA_T[1][byte(x[2] >> 8)] ^ KUPYNA_T[2][byte(x[1] >> 16)] ^ KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^ KUPYNA_T[5][byte(x[0] >> 40)] ^ KUPYNA_T[6][byte(x[3] >> 48)] ^ KUPYNA_T[7][byte(x[3] >> 56)])
    y[3] = k[3] + (KUPYNA_T[0][byte(x[3])] ^ KUPYNA_T[1][byte(x[3] >> 8)] ^ KUPYNA_T[2][byte(x[2] >> 16)] ^ KUPYNA_T[3][byte(x[2] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^ KUPYNA_T[5][byte(x[1] >> 40)] ^ KUPYNA_T[6][byte(x[0] >> 48)] ^ KUPYNA_T[7][byte(x[0] >> 56)])
}

func IMC256(x []uint64) {
    x[0] = IT[0][S[0][byte(x[0])]] ^ IT[1][S[1][byte(x[0] >> 8)]] ^ IT[2][S[2][byte(x[0] >> 16)]] ^ IT[3][S[3][byte(x[0] >> 24)]] ^
        IT[4][S[0][byte(x[0] >> 32)]] ^ IT[5][S[1][byte(x[0] >> 40)]] ^ IT[6][S[2][byte(x[0] >> 48)]] ^ IT[7][S[3][byte(x[0] >> 56)]]
    x[1] = IT[0][S[0][byte(x[1])]] ^ IT[1][S[1][byte(x[1] >> 8)]] ^ IT[2][S[2][byte(x[1] >> 16)]] ^ IT[3][S[3][byte(x[1] >> 24)]] ^
        IT[4][S[0][byte(x[1] >> 32)]] ^ IT[5][S[1][byte(x[1] >> 40)]] ^ IT[6][S[2][byte(x[1] >> 48)]] ^ IT[7][S[3][byte(x[1] >> 56)]]
    x[2] = IT[0][S[0][byte(x[2])]] ^ IT[1][S[1][byte(x[2] >> 8)]] ^ IT[2][S[2][byte(x[2] >> 16)]] ^ IT[3][S[3][byte(x[2] >> 24)]] ^
        IT[4][S[0][byte(x[2] >> 32)]] ^ IT[5][S[1][byte(x[2] >> 40)]] ^ IT[6][S[2][byte(x[2] >> 48)]] ^ IT[7][S[3][byte(x[2] >> 56)]]
    x[3] = IT[0][S[0][byte(x[3])]] ^ IT[1][S[1][byte(x[3] >> 8)]] ^ IT[2][S[2][byte(x[3] >> 16)]] ^ IT[3][S[3][byte(x[3] >> 24)]] ^
        IT[4][S[0][byte(x[3] >> 32)]] ^ IT[5][S[1][byte(x[3] >> 40)]] ^ IT[6][S[2][byte(x[3] >> 48)]] ^ IT[7][S[3][byte(x[3] >> 56)]]
}

func IG256(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] ^ IT[0][byte(x[0])] ^ IT[1][byte(x[0] >> 8)] ^ IT[2][byte(x[1] >> 16)] ^ IT[3][byte(x[1] >> 24)] ^
        IT[4][byte(x[2] >> 32)] ^ IT[5][byte(x[2] >> 40)] ^ IT[6][byte(x[3] >> 48)] ^ IT[7][byte(x[3] >> 56)]
    y[1] = k[1] ^ IT[0][byte(x[1])] ^ IT[1][byte(x[1] >> 8)] ^ IT[2][byte(x[2] >> 16)] ^ IT[3][byte(x[2] >> 24)] ^
        IT[4][byte(x[3] >> 32)] ^ IT[5][byte(x[3] >> 40)] ^ IT[6][byte(x[0] >> 48)] ^ IT[7][byte(x[0] >> 56)]
    y[2] = k[2] ^ IT[0][byte(x[2])] ^ IT[1][byte(x[2] >> 8)] ^ IT[2][byte(x[3] >> 16)] ^ IT[3][byte(x[3] >> 24)] ^
        IT[4][byte(x[0] >> 32)] ^ IT[5][byte(x[0] >> 40)] ^ IT[6][byte(x[1] >> 48)] ^ IT[7][byte(x[1] >> 56)]
    y[3] = k[3] ^ IT[0][byte(x[3])] ^ IT[1][byte(x[3] >> 8)] ^ IT[2][byte(x[0] >> 16)] ^ IT[3][byte(x[0] >> 24)] ^
        IT[4][byte(x[1] >> 32)] ^ IT[5][byte(x[1] >> 40)] ^ IT[6][byte(x[2] >> 48)] ^ IT[7][byte(x[2] >> 56)]
}

func IGL256(x []uint64, y []uint64, k []uint64) {
    y[0] = (uint64(IS[0][byte(x[0])]) ^ uint64(IS[1][byte(x[0] >> 8)]) << 8 ^ uint64(IS[2][byte(x[1] >> 16)]) << 16 ^ uint64(IS[3][byte(x[1] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[2] >> 32)]) << 32 ^ uint64(IS[1][byte(x[2] >> 40)]) << 40 ^ uint64(IS[2][byte(x[3] >> 48)]) << 48 ^ uint64(IS[3][byte(x[3] >> 56)]) << 56) - k[0]
    y[1] = (uint64(IS[0][byte(x[1])]) ^ uint64(IS[1][byte(x[1] >> 8)]) << 8 ^ uint64(IS[2][byte(x[2] >> 16)]) << 16 ^ uint64(IS[3][byte(x[2] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[3] >> 32)]) << 32 ^ uint64(IS[1][byte(x[3] >> 40)]) << 40 ^ uint64(IS[2][byte(x[0] >> 48)]) << 48 ^ uint64(IS[3][byte(x[0] >> 56)]) << 56) - k[1]
    y[2] = (uint64(IS[0][byte(x[2])]) ^ uint64(IS[1][byte(x[2] >> 8)]) << 8 ^ uint64(IS[2][byte(x[3] >> 16)]) << 16 ^ uint64(IS[3][byte(x[3] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[0] >> 32)]) << 32 ^ uint64(IS[1][byte(x[0] >> 40)]) << 40 ^ uint64(IS[2][byte(x[1] >> 48)]) << 48 ^ uint64(IS[3][byte(x[1] >> 56)]) << 56) - k[2]
    y[3] = (uint64(IS[0][byte(x[3])]) ^ uint64(IS[1][byte(x[3] >> 8)]) << 8 ^ uint64(IS[2][byte(x[0] >> 16)]) << 16 ^ uint64(IS[3][byte(x[0] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[1] >> 32)]) << 32 ^ uint64(IS[1][byte(x[1] >> 40)]) << 40 ^ uint64(IS[2][byte(x[2] >> 48)]) << 48 ^ uint64(IS[3][byte(x[2] >> 56)]) << 56) - k[3]
}

func swap_block256(k []uint64) {
    t := k[0]
    k[0] = k[1]
    k[1] = k[2]
    k[2] = k[3]
    k[3] = t
}

func add_constant256(src, dst []uint64, constant uint64) {
    var i int
    for i = 0; i < 4; i++ {
        dst[i] = src[i] + constant
    }
}

func make_odd_key256(evenkey []uint64, oddkey []uint64) {
    evenkeys := uint64sToBytes(evenkey)
    oddkeys := uint64sToBytes(oddkey)

    copy(oddkeys, evenkeys[11:32])
    copy(oddkeys[21:], evenkeys[:11])

    res := keyToUint64s(oddkeys)
    copy(oddkey, res)
}

// =============

func addkey128(x []uint64, y []uint64, k []uint64) {
    y[0] = x[0] + k[0]
    y[1] = x[1] + k[1]
}

func subkey128(x []uint64, y []uint64, k []uint64) {
    y[0] = x[0] - k[0]
    y[1] = x[1] - k[1]
}

func G0128(x []uint64, y []uint64) {
    y[0] = KUPYNA_T[0][byte(x[0])] ^ KUPYNA_T[1][byte(x[0] >> 8)] ^ KUPYNA_T[2][byte(x[0] >> 16)] ^ KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^ KUPYNA_T[5][byte(x[1] >> 40)] ^ KUPYNA_T[6][byte(x[1] >> 48)] ^ KUPYNA_T[7][byte(x[1] >> 56)]
    y[1] = KUPYNA_T[0][byte(x[1])] ^ KUPYNA_T[1][byte(x[1] >> 8)] ^ KUPYNA_T[2][byte(x[1] >> 16)] ^ KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^ KUPYNA_T[5][byte(x[0] >> 40)] ^ KUPYNA_T[6][byte(x[0] >> 48)] ^ KUPYNA_T[7][byte(x[0] >> 56)]
}

func G128(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] ^ KUPYNA_T[0][byte(x[0])] ^ KUPYNA_T[1][byte(x[0] >> 8)] ^ KUPYNA_T[2][byte(x[0] >> 16)] ^ KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^ KUPYNA_T[5][byte(x[1] >> 40)] ^ KUPYNA_T[6][byte(x[1] >> 48)] ^ KUPYNA_T[7][byte(x[1] >> 56)]
    y[1] = k[1] ^ KUPYNA_T[0][byte(x[1])] ^ KUPYNA_T[1][byte(x[1] >> 8)] ^ KUPYNA_T[2][byte(x[1] >> 16)] ^ KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^ KUPYNA_T[5][byte(x[0] >> 40)] ^ KUPYNA_T[6][byte(x[0] >> 48)] ^ KUPYNA_T[7][byte(x[0] >> 56)]
}

func GL128(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] + (KUPYNA_T[0][byte(x[0])] ^ KUPYNA_T[1][byte(x[0] >> 8)] ^ KUPYNA_T[2][byte(x[0] >> 16)] ^ KUPYNA_T[3][byte(x[0] >> 24)] ^
        KUPYNA_T[4][byte(x[1] >> 32)] ^ KUPYNA_T[5][byte(x[1] >> 40)] ^ KUPYNA_T[6][byte(x[1] >> 48)] ^ KUPYNA_T[7][byte(x[1] >> 56)])
    y[1] = k[1] + (KUPYNA_T[0][byte(x[1])] ^ KUPYNA_T[1][byte(x[1] >> 8)] ^ KUPYNA_T[2][byte(x[1] >> 16)] ^ KUPYNA_T[3][byte(x[1] >> 24)] ^
        KUPYNA_T[4][byte(x[0] >> 32)] ^ KUPYNA_T[5][byte(x[0] >> 40)] ^ KUPYNA_T[6][byte(x[0] >> 48)] ^ KUPYNA_T[7][byte(x[0] >> 56)])
}

func IMC128(x []uint64) {
    x[0] = IT[0][S[0][byte(x[0])]] ^ IT[1][S[1][byte(x[0] >> 8)]] ^ IT[2][S[2][byte(x[0] >> 16)]] ^ IT[3][S[3][byte(x[0] >> 24)]] ^
        IT[4][S[0][byte(x[0] >> 32)]] ^ IT[5][S[1][byte(x[0] >> 40)]] ^ IT[6][S[2][byte(x[0] >> 48)]] ^ IT[7][S[3][byte(x[0] >> 56)]]
    x[1] = IT[0][S[0][byte(x[1])]] ^ IT[1][S[1][byte(x[1] >> 8)]] ^ IT[2][S[2][byte(x[1] >> 16)]] ^ IT[3][S[3][byte(x[1] >> 24)]] ^
        IT[4][S[0][byte(x[1] >> 32)]] ^ IT[5][S[1][byte(x[1] >> 40)]] ^ IT[6][S[2][byte(x[1] >> 48)]] ^ IT[7][S[3][byte(x[1] >> 56)]]
}

func IG128(x []uint64, y []uint64, k []uint64) {
    y[0] = k[0] ^ IT[0][byte(x[0])] ^ IT[1][byte(x[0] >> 8)] ^ IT[2][byte(x[0] >> 16)] ^ IT[3][byte(x[0] >> 24)] ^
        IT[4][byte(x[1] >> 32)] ^ IT[5][byte(x[1] >> 40)] ^ IT[6][byte(x[1] >> 48)] ^ IT[7][byte(x[1] >> 56)]
    y[1] = k[1] ^ IT[0][byte(x[1])] ^ IT[1][byte(x[1] >> 8)] ^ IT[2][byte(x[1] >> 16)] ^ IT[3][byte(x[1] >> 24)] ^
        IT[4][byte(x[0] >> 32)] ^ IT[5][byte(x[0] >> 40)] ^ IT[6][byte(x[0] >> 48)] ^ IT[7][byte(x[0] >> 56)]
}

func IGL128(x []uint64, y []uint64, k []uint64) {
    y[0] = (uint64(IS[0][byte(x[0])]) ^ uint64(IS[1][byte(x[0] >> 8)]) << 8 ^ uint64(IS[2][byte(x[0] >> 16)]) << 16 ^ uint64(IS[3][byte(x[0] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[1] >> 32)]) << 32 ^ uint64(IS[1][byte(x[1] >> 40)]) << 40 ^ uint64(IS[2][byte(x[1] >> 48)]) << 48 ^ uint64(IS[3][byte(x[1] >> 56)]) << 56) - k[0]
    y[1] = (uint64(IS[0][byte(x[1])]) ^ uint64(IS[1][byte(x[1] >> 8)]) << 8 ^ uint64(IS[2][byte(x[1] >> 16)]) << 16 ^ uint64(IS[3][byte(x[1] >> 24)]) << 24 ^
        uint64(IS[0][byte(x[0] >> 32)]) << 32 ^ uint64(IS[1][byte(x[0] >> 40)]) << 40 ^ uint64(IS[2][byte(x[0] >> 48)]) << 48 ^ uint64(IS[3][byte(x[0] >> 56)]) << 56) - k[1]
}

func add_constant128(src []uint64, dst []uint64, constant uint64) {
    var i int
    for i = 0; i < 2; i++ {
        dst[i] = src[i] + constant;
    }
}

func make_odd_key128(evenkey []uint64, oddkey []uint64) {
    evenkeys := uint64sToBytes(evenkey)
    oddkeys := uint64sToBytes(oddkey)

    copy(oddkeys, evenkeys[7:16])
    copy(oddkeys[9:], evenkeys[:7])

    res := keyToUint64s(oddkeys)
    copy(oddkey, res)
}
