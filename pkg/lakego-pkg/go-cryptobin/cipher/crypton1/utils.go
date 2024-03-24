package crypton1

import (
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

// u4byte = uint32
// u1byte = byte

func rotr(x, n uint32) uint32 {
    return (x >> n) | (x << (32 - n))
}

func rotl(x, n uint32) uint32 {
    return (x << n) | (x >> (32 - n))
}

func Byte(x uint32, n uint32) uint32 {
    return uint32(byte(x >> (8 * n)))
}

func msk(n uint32) uint32 {
    return (0x000000ff >> n) * 0x01010101
}

func brotl(x, n uint32) uint32 {
    return (x & msk(n)) << n | (x & ^msk(n)) >> (8 - n)
}

func gamma_tau(b0 []uint32, b1 []uint32, i uint32) {
    b0[i] = uint32(s_box[(i + 2) & 3][Byte(b1[0], i)])       |
            uint32(s_box[(i + 3) & 3][Byte(b1[1], i)]) <<  8 |
            uint32(s_box[ i         ][Byte(b1[2], i)]) << 16 |
            uint32(s_box[(i + 1) & 3][Byte(b1[3], i)]) << 24
}

const (
    mb_0 = 0xcffccffc
    mb_1 = 0xf33ff33f
    mb_2 = 0xfccffccf
    mb_3 = 0x3ff33ff3
)

func row_perm(x uint32) uint32 {
    return (     x      & mb_0) ^
           (rotl(x,  8) & mb_1) ^
           (rotl(x, 16) & mb_2) ^
           (rotl(x, 24) & mb_3)
}

//  rotl(row_perm(x), 8)    row_perm(rotr(x,8))

func fr0(y []uint32, x []uint32, i, k uint32) {
    y[i] = s_tab[ i         ][Byte(x[0], i)] ^
           s_tab[(i + 1) & 3][Byte(x[1], i)] ^
           s_tab[(i + 2) & 3][Byte(x[2], i)] ^
           s_tab[(i + 3) & 3][Byte(x[3], i)] ^ k
}

func fr1(y []uint32, x []uint32, i, k uint32) {
    y[i] = s_tab[(i + 2) & 3][Byte(x[0], i)] ^
           s_tab[(i + 3) & 3][Byte(x[1], i)] ^
           s_tab[ i         ][Byte(x[2], i)] ^
           s_tab[(i + 1) & 3][Byte(x[3], i)] ^ k
}

func f0_rnd(b1 []uint32, b0 []uint32, kp []uint32) {
    fr0(b1, b0, 0, kp[0])
    fr0(b1, b0, 1, kp[1])
    fr0(b1, b0, 2, kp[2])
    fr0(b1, b0, 3, kp[3])
}

func f1_rnd(b0 []uint32, b1 []uint32, kp []uint32) {
    fr1(b0, b1, 0, kp[0])
    fr1(b0, b1, 1, kp[1])
    fr1(b0, b1, 2, kp[2])
    fr1(b0, b1, 3, kp[3])
}

const (
    mc0 = 0xacacacac
    mc1 = 0x59595959
    mc2 = 0xb2b2b2b2
    mc3 = 0x65656565
)

var  p0 = [16]byte{ 15, 14, 10,  1, 11,  5,  8, 13,  9,  3,  2,  7,  0,  6,  4, 12 };
var  p1 = [16]byte{ 11, 10, 13,  7,  8, 14,  0,  5, 15,  6,  3,  4,  1,  9,  2, 12 };
var ip0 = [16]byte{ 12,  3, 10,  9, 14,  5, 13, 11,  6,  8,  2,  4, 15,  7,  1,  0 };
var ip1 = [16]byte{  6, 12, 14, 10, 11,  7,  9,  3,  4, 13,  1,  0, 15,  2,  5,  8 };

var kp = [4]uint32{ 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f };
var kq = [4]uint32{ 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, 0xcbbb9d5d };

var s_box [4][256]uint32
var s_tab [4][256]uint32
var ce [52]uint32
var cd [52]uint32

func gen_tab() {
    var i, xl, xr, y, yl, yr uint32

    for i = 0; i < 256; i++ {
        xl = uint32(p1[i >> 4])
        xr = uint32(p0[i & 15])

        yl  = (xl & 0x0e) ^
            ((xl << 3) & 0x08) ^ ((xl >> 3) & 0x01) ^
            ((xr << 1) & 0x0a) ^ ((xr << 2) & 0x04) ^
            ((xr >> 2) & 0x02) ^ ((xr >> 1) & 0x01)

        yr  = (xr & 0x0d) ^
            ((xr << 1) & 0x04) ^ ((xr >> 1) & 0x02) ^
            ((xl >> 1) & 0x05) ^ ((xl << 2) & 0x08) ^
            ((xl << 1) & 0x02) ^ ((xl >> 2) & 0x01)

        y = uint32(ip0[yl] | (ip1[yr] << 4))

        yr = ((y << 3) | (y >> 5)) & 255
        xr = ((i << 3) | (i >> 5)) & 255
        yl = ((y << 1) | (y >> 7)) & 255
        xl = ((i << 1) | (i >> 7)) & 255

        s_box[0][i]  = uint32(byte(yl))
        s_box[1][i]  = uint32(byte(yr))
        s_box[2][xl] = uint32(byte(y))
        s_box[3][xr] = uint32(byte(y))

        s_tab[0][ i] = (yl * 0x01010101) & 0x3fcff3fc
        s_tab[1][ i] = (yr * 0x01010101) & 0xfc3fcff3
        s_tab[2][xl] = (y * 0x01010101) & 0xf3fc3fcf
        s_tab[3][xr] = (y * 0x01010101) & 0xcff3fc3f
    }

    xl = 0xa54ff53a

    for i = 0; i < 13; i++ {
        ce[4 * i + 0] = xl ^ mc0
        ce[4 * i + 1] = xl ^ mc1
        ce[4 * i + 2] = xl ^ mc2
        ce[4 * i + 3] = xl ^ mc3

        if (i & 1) > 0 {
            yl = row_perm(xl)
        } else {
            yl = row_perm(rotr(xl, 16))
        }

        cd[4 * (12 - i) + 0] = yl ^ mc0
        cd[4 * (12 - i) + 1] = rotl(yl, 24) ^ mc1
        cd[4 * (12 - i) + 2] = rotl(yl, 16) ^ mc2
        cd[4 * (12 - i) + 3] = rotl(yl,  8) ^ mc3

        xl += 0x3c6ef372
    }
}


