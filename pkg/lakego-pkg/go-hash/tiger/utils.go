package tiger

var littleEndian bool = true

func round(a, b, c, x, mul uint64) (uint64, uint64, uint64) {
    c ^= x

    a -= t1[ c        & 0xff] ^
         t2[(c >> 16) & 0xff] ^
         t3[(c >> 32) & 0xff] ^
         t4[(c >> 48) & 0xff]

    b += t4[(c >>  8) & 0xff] ^
         t3[(c >> 24) & 0xff] ^
         t2[(c >> 40) & 0xff] ^
         t1[(c >> 56) & 0xff]

    b *= mul

    return a, b, c
}

func pass(a, b, c uint64, x []uint64, mul uint64) (uint64, uint64, uint64) {
    a, b, c = round(a, b, c, x[0], mul)
    b, c, a = round(b, c, a, x[1], mul)
    c, a, b = round(c, a, b, x[2], mul)
    a, b, c = round(a, b, c, x[3], mul)
    b, c, a = round(b, c, a, x[4], mul)
    c, a, b = round(c, a, b, x[5], mul)
    a, b, c = round(a, b, c, x[6], mul)
    b, c, a = round(b, c, a, x[7], mul)

    return a, b, c
}

func keySchedule(x []uint64) {
    x[0] -= x[7] ^ 0xa5a5a5a5a5a5a5a5
    x[1] ^= x[0]
    x[2] += x[1]
    x[3] -= x[2] ^ ((^x[1]) << 19)
    x[4] ^= x[3]
    x[5] += x[4]
    x[6] -= x[5] ^ ((^x[4]) >> 23)
    x[7] ^= x[6]
    x[0] += x[7]
    x[1] -= x[0] ^ ((^x[7]) << 19)
    x[2] ^= x[1]
    x[3] += x[2]
    x[4] -= x[3] ^ ((^x[2]) >> 23)
    x[5] ^= x[4]
    x[6] += x[5]
    x[7] -= x[6] ^ 0x0123456789abcdef
}
