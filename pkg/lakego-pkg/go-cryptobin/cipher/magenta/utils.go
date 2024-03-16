package magenta

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

func Byte(x uint32, n int) uint32 {
    return uint32(byte(x >> (8 * n)))
}

const GF_POLY = 0x0165

var f_tab [256]uint32

func init_tab() {
    var i, f uint32

    f = 1

    for i = 0; i < 255; i++ {
        f_tab[i] = uint32(byte(f))

        f <<= 1

        if (f & 0x100) > 0 {
            f ^= GF_POLY
        }
    }

    f_tab[255] = 0
}

func pi_fun(y *[4]uint32, x [4]uint32) {
    y[0] = f_tab[Byte(x[0], 0) ^ f_tab[Byte(x[2], 0)]]         |
           (f_tab[Byte(x[2], 0) ^ f_tab[Byte(x[0], 0)]] <<  8) |
           (f_tab[Byte(x[0], 1) ^ f_tab[Byte(x[2], 1)]] << 16) |
           (f_tab[Byte(x[2], 1) ^ f_tab[Byte(x[0], 1)]] << 24)

    y[1] = f_tab[Byte(x[0], 2) ^ f_tab[Byte(x[2], 2)]]         |
           (f_tab[Byte(x[2], 2) ^ f_tab[Byte(x[0], 2)]] <<  8) |
           (f_tab[Byte(x[0], 3) ^ f_tab[Byte(x[2], 3)]] << 16) |
           (f_tab[Byte(x[2], 3) ^ f_tab[Byte(x[0], 3)]] << 24)

    y[2] = f_tab[Byte(x[1], 0) ^ f_tab[Byte(x[3], 0)]] |
        (f_tab[Byte(x[3], 0) ^ f_tab[Byte(x[1], 0)]] <<  8) |
        (f_tab[Byte(x[1], 1) ^ f_tab[Byte(x[3], 1)]] << 16) |
        (f_tab[Byte(x[3], 1) ^ f_tab[Byte(x[1], 1)]] << 24)

    y[3] = f_tab[Byte(x[1], 2) ^ f_tab[Byte(x[3], 2)]] |
           (f_tab[Byte(x[3], 2) ^ f_tab[Byte(x[1], 2)]] <<  8) |
           (f_tab[Byte(x[1], 3) ^ f_tab[Byte(x[3], 3)]] << 16) |
           (f_tab[Byte(x[3], 3) ^ f_tab[Byte(x[1], 3)]] << 24)
}

func e3_fun(x *[4]uint32) {
    var u, v [4]uint32

    u[0] = x[0]
    u[1] = x[1]
    u[2] = x[2]
    u[3] = x[3]

    pi_fun(&v, u)
    pi_fun(&u, v)
    pi_fun(&v, u)
    pi_fun(&u, v)

    v[0] = Byte(u[0], 0) | (Byte(u[0], 2) << 8) | (Byte(u[1], 0) << 16) | (Byte(u[1], 2) << 24)
    v[1] = Byte(u[2], 0) | (Byte(u[2], 2) << 8) | (Byte(u[3], 0) << 16) | (Byte(u[3], 2) << 24)
    v[2] = Byte(u[0], 1) | (Byte(u[0], 3) << 8) | (Byte(u[1], 1) << 16) | (Byte(u[1], 3) << 24)
    v[3] = Byte(u[2], 1) | (Byte(u[2], 3) << 8) | (Byte(u[3], 1) << 16) | (Byte(u[3], 3) << 24)

    u[0] = x[0] ^ v[0]
    u[1] = x[1] ^ v[1]
    u[2] = x[2] ^ v[2]
    u[3] = x[3] ^ v[3]

    pi_fun(&v, u)
    pi_fun(&u, v)
    pi_fun(&v, u)
    pi_fun(&u, v)

    v[0] = Byte(u[0], 0) | (Byte(u[0], 2) << 8) | (Byte(u[1], 0) << 16) | (Byte(u[1], 2) << 24)
    v[1] = Byte(u[2], 0) | (Byte(u[2], 2) << 8) | (Byte(u[3], 0) << 16) | (Byte(u[3], 2) << 24)
    v[2] = Byte(u[0], 1) | (Byte(u[0], 3) << 8) | (Byte(u[1], 1) << 16) | (Byte(u[1], 3) << 24)
    v[3] = Byte(u[2], 1) | (Byte(u[2], 3) << 8) | (Byte(u[3], 1) << 16) | (Byte(u[3], 3) << 24)

    u[0] = x[0] ^ v[0]
    u[1] = x[1] ^ v[1]
    u[2] = x[2] ^ v[2]
    u[3] = x[3] ^ v[3]

    pi_fun(&v, u)
    pi_fun(&u, v)
    pi_fun(&v, u)
    pi_fun(&u, v)

    v[0] = Byte(u[0], 0) | (Byte(u[0], 2) << 8) | (Byte(u[1], 0) << 16) | (Byte(u[1], 2) << 24)
    v[1] = Byte(u[2], 0) | (Byte(u[2], 2) << 8) | (Byte(u[3], 0) << 16) | (Byte(u[3], 2) << 24)
    v[2] = Byte(u[0], 1) | (Byte(u[0], 3) << 8) | (Byte(u[1], 1) << 16) | (Byte(u[1], 3) << 24)
    v[3] = Byte(u[2], 1) | (Byte(u[2], 3) << 8) | (Byte(u[3], 1) << 16) | (Byte(u[3], 3) << 24)

    x[0] = v[0]
    x[1] = v[1]
}

func r_fun(tt *[4]uint32, x, y, k []uint32) {
    tt[0] = y[0]
    tt[1] = y[1]
    tt[2] = k[0]
    tt[3] = k[1]

    e3_fun(tt)

    x[0] ^= tt[0]
    x[1] ^= tt[1]
}
