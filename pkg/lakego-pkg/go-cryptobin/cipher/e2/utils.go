package e2

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

func rotr(x, n uint32) uint32 {
    return (x >> n) | (x << (32 - n))
}

func rotl(x, n uint32) uint32 {
    return (x << n) | (x >> (32 - n))
}

func bswap(x uint32) uint32 {
    return (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00)
}

func io_swap(x uint32) uint32 {
    return bswap(x)
}

var s_box = []byte{
    0xe1, 0x42, 0x3e, 0x81, 0x4e, 0x17, 0x9e, 0xfd, 0xb4, 0x3f, 0x2c, 0xda,
    0x31, 0x1e, 0xe0, 0x41, 0xcc, 0xf3, 0x82, 0x7d, 0x7c, 0x12, 0x8e, 0xbb,
    0xe4, 0x58, 0x15, 0xd5, 0x6f, 0xe9, 0x4c, 0x4b, 0x35, 0x7b, 0x5a, 0x9a,
    0x90, 0x45, 0xbc, 0xf8, 0x79, 0xd6, 0x1b, 0x88, 0x02, 0xab, 0xcf, 0x64,
    0x09, 0x0c, 0xf0, 0x01, 0xa4, 0xb0, 0xf6, 0x93, 0x43, 0x63, 0x86, 0xdc,
    0x11, 0xa5, 0x83, 0x8b, 0xc9, 0xd0, 0x19, 0x95, 0x6a, 0xa1, 0x5c, 0x24,
    0x6e, 0x50, 0x21, 0x80, 0x2f, 0xe7, 0x53, 0x0f, 0x91, 0x22, 0x04, 0xed,
    0xa6, 0x48, 0x49, 0x67, 0xec, 0xf7, 0xc0, 0x39, 0xce, 0xf2, 0x2d, 0xbe,
    0x5d, 0x1c, 0xe3, 0x87, 0x07, 0x0d, 0x7a, 0xf4, 0xfb, 0x32, 0xf5, 0x8c,
    0xdb, 0x8f, 0x25, 0x96, 0xa8, 0xea, 0xcd, 0x33, 0x65, 0x54, 0x06, 0x8d,
    0x89, 0x0a, 0x5e, 0xd9, 0x16, 0x0e, 0x71, 0x6c, 0x0b, 0xff, 0x60, 0xd2,
    0x2e, 0xd3, 0xc8, 0x55, 0xc2, 0x23, 0xb7, 0x74, 0xe2, 0x9b, 0xdf, 0x77,
    0x2b, 0xb9, 0x3c, 0x62, 0x13, 0xe5, 0x94, 0x34, 0xb1, 0x27, 0x84, 0x9f,
    0xd7, 0x51, 0x00, 0x61, 0xad, 0x85, 0x73, 0x03, 0x08, 0x40, 0xef, 0x68,
    0xfe, 0x97, 0x1f, 0xde, 0xaf, 0x66, 0xe8, 0xb8, 0xae, 0xbd, 0xb3, 0xeb,
    0xc6, 0x6b, 0x47, 0xa9, 0xd8, 0xa7, 0x72, 0xee, 0x1d, 0x7e, 0xaa, 0xb6,
    0x75, 0xcb, 0xd4, 0x30, 0x69, 0x20, 0x7f, 0x37, 0x5b, 0x9d, 0x78, 0xa3,
    0xf1, 0x76, 0xfa, 0x05, 0x3d, 0x3a, 0x44, 0x57, 0x3b, 0xca, 0xc7, 0x8a,
    0x18, 0x46, 0x9c, 0xbf, 0xba, 0x38, 0x56, 0x1a, 0x92, 0x4d, 0x26, 0x29,
    0xa2, 0x98, 0x10, 0x99, 0x70, 0xa0, 0xc5, 0x28, 0xc1, 0x6d, 0x14, 0xac,
    0xf9, 0x5f, 0x4f, 0xc4, 0xc3, 0xd1, 0xfc, 0xdd, 0xb2, 0x59, 0xe6, 0xb5,
    0x36, 0x52, 0x4a, 0x2a,
}

const (
    v_0 = 0x67452301
    v_1 = 0xefcdab89

    /* s_fun(s_fun(s_fun(v)))           */

    k2_0 = 0x30d32e58
    k2_1 = 0xb89e4984

    /* s_fun(s_fun(s_fun(s_fun(v))))    */

    k3_0 = 0x0957cfec
    k3_1 = 0xd800502e
)

var l_box [4][256]uint32

func bp_fun(u, v, a, b, c, d *uint32, e, f, g, h uint32) {
    (*u) = (e ^ g) & 0x00ffff00
    (*v) = (f ^ h) & 0x0000ffff

    (*a) = e ^ (*u)
    (*c) = g ^ (*u)
    (*b) = f ^ (*v)
    (*d) = h ^ (*v)
}

func ibp_fun(u, v, a, b, c, d *uint32, e, f, g, h uint32) {
    (*u) = (e ^ g) & 0xff0000ff
    (*v) = (f ^ h) & 0xffff0000

    (*a) = e ^ (*u)
    (*c) = g ^ (*u)
    (*b) = f ^ (*v)
    (*d) = h ^ (*v)
}

func bp2_fun(w, x, y *uint32) {
    (*w) = ((*x) ^ (*y)) & 0x00ff00ff

    (*x) ^= (*w)
    (*y) ^= (*w)
}

func s_fun(p, q, r, s, x, y *uint32) {
    (*p) = (*x)
    (*q) = (*x) >> 8
    (*r) = (*y)
    (*s) = (*y) >> 8

    (*x)  = l_box[0][(*r) & 255]
    (*y)  = l_box[0][(*p) & 255]

    (*p) >>= 16
    (*r) >>= 16

    (*x) |= l_box[1][(*q) & 255]
    (*y) |= l_box[1][(*s) & 255]
    (*x) |= l_box[2][(*r) & 255]
    (*y) |= l_box[2][(*p) & 255]
    (*x) |= l_box[3][(*p) >> 8]
    (*y) |= l_box[3][(*r) >> 8]
}

func sx_fun(p, q, x, y *uint32) {
    (*p) = (*x) >>  8
    (*q) = (*x) >> 16

    (*x)  = l_box[0][(*x) & 255]
    (*x) |= l_box[1][(*p) & 255]
    (*x) |= l_box[2][(*q) & 255]
    (*x) |= l_box[3][(*q) >> 8]

    (*p) = (*y) >>  8
    (*q) = (*y) >> 16

    (*y)  = l_box[0][(*y) & 255]
    (*y) |= l_box[1][(*p) & 255]
    (*y) |= l_box[2][(*q) & 255]
    (*y) |= l_box[3][(*q) >> 8]
}

func spx_fun(p, q, x, y *uint32) {
    sx_fun(p, q, x, y)

    (*y) ^= (*x)
    (*x) ^= rotr((*y), 16)
    (*y) ^= rotr((*x), 8)
    (*x) ^= (*y)
}

func sp_fun(p, q, r, s, x, y *uint32) {
    s_fun(p, q, r, s, x, y)

    (*y) ^= (*x)
    (*x) ^= rotr((*y), 16)
    (*y) ^= rotr((*x), 8)
    (*x) ^= (*y)
}

func sr_fun(p, q, r, s, x, y *uint32) {
    (*p) = (*x)
    (*q) = (*x) >> 8
    (*r) = (*y)
    (*s) = (*y) >> 8

    (*y)  = l_box[1][(*p) & 255]
    (*x)  = l_box[1][(*r) & 255]

    (*p) >>= 16
    (*r) >>= 16

    (*x) |= l_box[2][(*q) & 255]
    (*y) |= l_box[2][(*s) & 255]
    (*y) |= l_box[3][(*p) & 255]
    (*x) |= l_box[3][(*r) & 255]
    (*x) |= l_box[0][(*r) >>  8]
    (*y) |= l_box[0][(*p) >>  8]
}

func f_fun(p, q, r, s, u, v, a, b *uint32, c, d uint32, k []uint32) {
    (*u) = c ^ k[0]
    (*v) = d ^ k[1]

    sp_fun(p, q, r, s, u, v)

    (*u) ^= k[2]
    (*v) ^= k[3]

    sr_fun(p, q, r, s, u, v)

    (*a) ^= (*v)
    (*b) ^= (*u)
}

func mod_inv(x uint32) uint32 {
    var y1, y2, a, b, q uint32

    y1 = ^((-x) / x)
    y2 = 1

    a = x
    b = y1 * x

    for ;; {
        q = a / b

        a -= (q * b)

        if a == 0 {
            if x * y1 == 1 {
                return y1
            } else {
                return -y1
            }
        }

        y2 -= (q * y1)

        q = b / a

        b -= (q * a)

        if b == 0 {
            if x * y2 == 1 {
                return y2
            } else {
                return -y2
            }
        }

        y1 -= (q * y2)
    }
}

func g_fun(y [8]uint32, l [8]uint32, v [2]uint32) ([8]uint32, [2]uint32) {
    var p, q uint32

    spx_fun(&p, &q, &y[0], &y[1])
    spx_fun(&p, &q, &v[0], &v[1])

    v[0] ^= y[0]
    l[0] = v[0]

    v[1] ^= y[1]
    l[1] = v[1]

    spx_fun(&p, &q, &y[2], &y[3])
    spx_fun(&p, &q, &v[0], &v[1])

    v[0] ^= y[2]
    l[2] = v[0]

    v[1] ^= y[3]
    l[3] = v[1]

    spx_fun(&p, &q, &y[4], &y[5])
    spx_fun(&p, &q, &v[0], &v[1])

    v[0] ^= y[4]
    l[4] = v[0]

    v[1] ^= y[5]
    l[5] = v[1]

    spx_fun(&p, &q, &y[6], &y[7])
    spx_fun(&p, &q, &v[0], &v[1])

    v[0] ^= y[6]
    l[6] = v[0]

    v[1] ^= y[7]
    l[7] = v[1]

    return l, v
}

func init_box() {
    var i uint32

    for i = 0; i < 256; i++ {
        l_box[0][i] = uint32(s_box[i])
        l_box[1][i] = uint32(s_box[i]) <<  8
        l_box[2][i] = uint32(s_box[i]) << 16
        l_box[3][i] = uint32(s_box[i]) << 24
    }
}

