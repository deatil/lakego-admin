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

