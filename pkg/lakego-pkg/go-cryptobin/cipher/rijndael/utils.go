package rijndael

/* Inverse Coefficients */
var inCo = [4]byte{ 0xB, 0xD, 0x9, 0xE }

var fbsub [256]byte
var rbsub [256]byte
var ptab, ltab [256]byte
var ftable [256]uint32
var rtable [256]uint32
var rco [30]uint32

func rotl(x byte) byte {
    return (x >> 7) | (x << 1)
}

func rotl8(x uint32) uint32 {
    return (x << 8) | (x >> 24)
}

func rotl16(x uint32) uint32 {
    return (x << 16) | (x >> 16)
}

func rotl24(x uint32) uint32 {
    return (x << 24) | (x >> 8)
}

func pack(b []byte) uint32 {
    /* pack bytes into a 32-bit Word */
    return uint32(b[3]) << 24 |
           uint32(b[2]) << 16 |
           uint32(b[1]) <<  8 |
           uint32(b[0])
}

func unpack(a uint32, b []byte) {
    /* unpack bytes from a word */
    b[0] = byte(a)
    b[1] = byte(a >>  8)
    b[2] = byte(a >> 16)
    b[3] = byte(a >> 24)
}

func xtime(a byte) byte {
    var b byte

    if (a & 0x80) > 0{
        b = 0x1B
    } else {
        b = 0
    }

    a <<= 1
    a ^= b

    return a
}

func bmul(x byte, y byte) byte {
    if x > 0 && y > 0 {
        return ptab[(int(ltab[x]) + int(ltab[y])) % 255]
    }

    return 0
}

func subByte(a uint32) uint32 {
    var b [4]byte
    unpack(a, b[:])

    b[0] = fbsub[b[0]]
    b[1] = fbsub[b[1]]
    b[2] = fbsub[b[2]]
    b[3] = fbsub[b[3]]

    return pack(b[:])
}

func product(x uint32, y uint32) byte {
    /* dot product of two 4-byte arrays */
    var xb, yb [4]byte

    unpack(x, xb[:])
    unpack(y, yb[:])

    return bmul(xb[0], yb[0]) ^
           bmul(xb[1], yb[1]) ^
           bmul(xb[2], yb[2]) ^
           bmul(xb[3], yb[3])
}

func invMixCol(x uint32) uint32 {
    /* matrix Multiplication */
    var y, m uint32
    var b [4]byte

    m = pack(inCo[:])
    b[3] = product(m, x)

    m = rotl24(m);
    b[2] = product(m, x)

    m = rotl24(m);
    b[1] = product(m, x)

    m = rotl24(m);
    b[0] = product(m, x)

    y = pack(b[:])

    return y
}

func byteSub(x byte) byte {
    /* multiplicative inverse */
    var y byte = ptab[255 - ltab[x]]

    x = y

    x = rotl(x)
    y ^= x

    x = rotl(x)
    y ^= x

    x = rotl(x)
    y ^= x

    x = rotl(x)
    y ^= x

    y ^= 0x63

    return y
}

func genTables() {
    /* generate tables */
    var i int32
    var y byte
    var b [4]byte

    /* use 3 as primitive root to generate power and log tables */

    ltab[0] = 0
    ptab[0] = 1
    ltab[1] = 0
    ptab[1] = 3
    ltab[3] = 1

    for i = 2; i < 256; i++ {
        ptab[i] = ptab[i - 1] ^ xtime(ptab[i - 1])
        ltab[ptab[i]] = byte(i)
    }

    /* affine transformation:- each bit is xored with itself shifted one bit */

    fbsub[0] = 0x63
    rbsub[0x63] = 0
    for i = 1; i < 256; i++ {
        y = byteSub(byte(i))
        fbsub[i] = y
        rbsub[y] = byte(i)
    }

    for i, y = 0, 1; i < 30; i++ {
        rco[i] = uint32(y)
        y = xtime(y)
    }

    /* calculate forward and reverse tables */
    for i = 0; i < 256; i++ {
        y = fbsub[i]
        b[3] = y ^ xtime(y)
        b[2] = y
        b[1] = y
        b[0] = xtime(y)
        ftable[i] = pack(b[:])

        y = rbsub[i]
        b[3] = bmul(inCo[0], y)
        b[2] = bmul(inCo[1], y)
        b[1] = bmul(inCo[2], y)
        b[0] = bmul(inCo[3], y)
        rtable[i] = pack(b[:])
    }
}
