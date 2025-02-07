package groestl

import (
    "encoding/binary"
)

func GETU64(ptr []byte) uint64 {
    return binary.LittleEndian.Uint64(ptr)
}

func PUTU64(ptr []byte, a uint64) {
    binary.LittleEndian.PutUint64(ptr, a)
}

func bytesToUint64s(b []byte) []uint64 {
    size := len(b) / 8
    dst := make([]uint64, size)

    for i := 0; i < size; i++ {
        j := i * 8

        dst[i] = binary.LittleEndian.Uint64(b[j:])
    }

    return dst
}

func uint64sToBytes(w []uint64) []byte {
    size := len(w) * 8
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 8

        binary.LittleEndian.PutUint64(dst[j:], w[i])
    }

    return dst
}

func swap_uint64(val uint64) uint64 {
    return ((val & 0xff00000000000000) >> 56) |
           ((val & 0x00ff000000000000) >> 40) |
           ((val & 0x0000ff0000000000) >> 24) |
           ((val & 0x000000ff00000000) >>  8) |
           ((val & 0x00000000ff000000) <<  8) |
           ((val & 0x0000000000ff0000) << 24) |
           ((val & 0x000000000000ff00) << 40) |
           ((val & 0x00000000000000ff) << 56)
}

func roundP_256(x, y *[8]uint64, i uint64) {
    var idx int
    for idx = 0; idx < 8; idx++ {
       x[idx] ^= (uint64(idx) << 4) ^ i
    }

    var c int
    for c = 0; c < 8; c++ {
        y[c] = T[0][byte(x[(c + 0) % 8]      )] ^
               T[1][byte(x[(c + 1) % 8] >>  8)] ^
               T[2][byte(x[(c + 2) % 8] >> 16)] ^
               T[3][byte(x[(c + 3) % 8] >> 24)] ^
               T[4][byte(x[(c + 4) % 8] >> 32)] ^
               T[5][byte(x[(c + 5) % 8] >> 40)] ^
               T[6][byte(x[(c + 6) % 8] >> 48)] ^
               T[7][byte(x[(c + 7) % 8] >> 56)]
    }
}

func roundQ_256(x, y *[8]uint64, i uint64) {
    var idx int
    for idx = 0; idx < 8; idx++ {
        x[idx] ^= (0xffffffffffffffff - (uint64(idx) << 60)) ^ i
    }

    var c int
    for c = 0; c < 8; c++ {
        y[c] = T[0][byte(x[(c + 1) % 8]      )] ^
               T[1][byte(x[(c + 3) % 8] >>  8)] ^
               T[2][byte(x[(c + 5) % 8] >> 16)] ^
               T[3][byte(x[(c + 7) % 8] >> 24)] ^
               T[4][byte(x[(c + 0) % 8] >> 32)] ^
               T[5][byte(x[(c + 2) % 8] >> 40)] ^
               T[6][byte(x[(c + 4) % 8] >> 48)] ^
               T[7][byte(x[(c + 6) % 8] >> 56)]
    }
}

func roundP_512(x, y *[16]uint64, i uint64) {
    var idx int
    for idx = 0; idx < 16; idx++ {
        x[idx] ^= (uint64(idx) << 4) ^ i;
    }

    var c int
    for c = 15; c >= 0; c-- {
        y[c] = T[0][byte(x[(c +  0) % 16]      )] ^
               T[1][byte(x[(c +  1) % 16] >>  8)] ^
               T[2][byte(x[(c +  2) % 16] >> 16)] ^
               T[3][byte(x[(c +  3) % 16] >> 24)] ^
               T[4][byte(x[(c +  4) % 16] >> 32)] ^
               T[5][byte(x[(c +  5) % 16] >> 40)] ^
               T[6][byte(x[(c +  6) % 16] >> 48)] ^
               T[7][byte(x[(c + 11) % 16] >> 56)]
    }
}

func roundQ_512(x, y *[16]uint64, i uint64) {
    var idx int
    for idx = 0; idx < 16; idx++ {
        x[idx] ^= (0xffffffffffffffff - (uint64(idx) << 60)) ^ i
    }

    var c int
    for c = 15; c >= 0; c-- {
        y[c] = T[0][byte(x[(c+ 1)%16]      )] ^
               T[1][byte(x[(c+ 3)%16] >>  8)] ^
               T[2][byte(x[(c+ 5)%16] >> 16)] ^
               T[3][byte(x[(c+11)%16] >> 24)] ^
               T[4][byte(x[(c+ 0)%16] >> 32)] ^
               T[5][byte(x[(c+ 2)%16] >> 40)] ^
               T[6][byte(x[(c+ 4)%16] >> 48)] ^
               T[7][byte(x[(c+ 6)%16] >> 56)]
    }
}

func transform256(h *[16]uint64, m []uint64) {
    var AQ1, AQ2, AP1, AP2 [8]uint64

    _ = m[15]

    var column int
    for column = 0; column < 8; column++ {
        AP1[column] = h[column] ^ m[column]
        AQ1[column] = m[column]
    }

    var r uint64
    for r = 0; r < 10; r += 2 {
        roundP_256(&AP1, &AP2, r)
        roundP_256(&AP2, &AP1, r + 1)
        roundQ_256(&AQ1, &AQ2, r << 56)
        roundQ_256(&AQ2, &AQ1, (r + 1) << 56)
    }

    for column = 0; column < 8; column++ {
        h[column] = AP1[column] ^ AQ1[column] ^ h[column]
    }
}

func transform512(h *[16]uint64, m []uint64) {
    var AQ1, AQ2, AP1, AP2 [16]uint64

    _ = m[15]

    var column int
    for column = 0; column < 16; column++ {
        AP1[column] = h[column] ^ m[column]
        AQ1[column] = m[column]
    }

    var r uint64
    for r = 0; r < 14; r += 2 {
        roundP_512(&AP1, &AP2, r)
        roundP_512(&AP2, &AP1, r + 1)
        roundQ_512(&AQ1, &AQ2, r << 56)
        roundQ_512(&AQ2, &AQ1, (r + 1) << 56)
    }

    for column = 0; column < 16; column++ {
        h[column] = AP1[column] ^ AQ1[column] ^ h[column]
    }
}

func outputTransform256(h *[16]uint64) {
    var t1 [8]uint64
    var t2 [8]uint64

    var column int
    for column = 0; column < 8; column++ {
        t1[column] = h[column]
    }

    var r uint64
    for r = 0; r < 10; r += 2 {
        roundP_256(&t1, &t2, r)
        roundP_256(&t2, &t1, r + 1)
    }

    for column = 0; column < 8; column++ {
        h[column] ^= t1[column]
    }
}

func outputTransform512(h *[16]uint64) {
    var t1 [16]uint64
    var t2 [16]uint64

    var column int
    for column = 0; column < 16; column++ {
        t1[column] = h[column]
    }

    var r uint64
    for r = 0; r < 14; r += 2 {
        roundP_512(&t1, &t2, r)
        roundP_512(&t2, &t1, r + 1)
    }

    for column = 0; column < 16; column++ {
        h[column] ^= t1[column]
    }
}
