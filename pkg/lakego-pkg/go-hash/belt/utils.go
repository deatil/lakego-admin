package belt

import (
    "math/bits"
    "encoding/binary"
)

const BELT_HASH_BLOCK_SIZE       = 32
const BELT_HASH_DIGEST_SIZE      = 32
const BELT_HASH_DIGEST_SIZE_BITS = 256

const BELT_BLOCK_LEN     = 16 /* The BELT encryption block length */
const BELT_KEY_SCHED_LEN = 32 /* The BELT key schedul length */

// Endianness option
const littleEndian bool = true

func getu32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func putu32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
    }
}

func getu64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func putu64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
    }
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

func rotatel32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func rotater32(x uint32, n int) uint32 {
    return rotatel32(x, 32 - n)
}

func ROTL_BELT(x uint32, n int) uint32 {
    return rotater32(x, n)
}

func GET_BYTE(x uint32, a int) byte {
    return byte(x >> a) & 0xff
}

func PUT_BYTE(x uint32, a int) uint32 {
    return x << a
}

func SB(x uint32, a int) uint32 {
    return PUT_BYTE(uint32(S[GET_BYTE(x, a)]), a)
}

func G(x uint32, r int) uint32 {
    return ROTL_BELT(SB(x, 24) | SB(x, 16) | SB(x, 8) | SB(x, 0), r)
}

func belt_init(k []byte, ks *[BELT_KEY_SCHED_LEN]byte) {
    var i int

    k_len := len(k)

    switch (k_len) {
        case 16:
            for i = 0; i < 16; i++ {
                ks[i]      = k[i]
                ks[i + 16] = k[i]
            }

        case 24:
            for i = 0; i < 24; i++ {
                ks[i] = k[i]
            }

            for i = 24; i < 32; i++ {
                ks[i] = k[i - 24] ^ k[i - 20] ^ k[i - 16]
            }
        case 32:
            for i = 0; i < 32; i++ {
                ks[i] = k[i]
            }
    }

}

func belt_encrypt(in [BELT_BLOCK_LEN]byte, out *[BELT_BLOCK_LEN]byte, ks [BELT_KEY_SCHED_LEN]byte) {
    var a, b, c, d, e uint32
    var i uint32

    a = getu32(in[0:])
    b = getu32(in[4:])
    c = getu32(in[8:])
    d = getu32(in[12:])

    for i = 0; i < 8; i++ {
        var key uint32

        key = getu32(ks[4*KIdx[i][0]:])
        b ^= G(a + key, 5)

        key = getu32(ks[4*KIdx[i][1]:])
        c ^= G(d + key, 21)

        key = getu32(ks[4*KIdx[i][2]:])
        a = (a - G(b + key, 13))

        key = getu32(ks[4*KIdx[i][3]:])
        e = G(b + c + key, 21) ^ (i + 1)

        b += e
        c = (c - e)

        key = getu32(ks[4*KIdx[i][4]:])
        d += G(c + key, 13)

        key = getu32(ks[4*KIdx[i][5]:])
        b ^= G(a + key, 21)

        key = getu32(ks[4*KIdx[i][6]:])
        c ^= G(d + key, 5)

        a, b = b, a
        c, d = d, c
        b, c = c, b
    }

    putu32(out[0:], b)
    putu32(out[4:], d)
    putu32(out[8:], a)
    putu32(out[12:], c)
}

func belt_decrypt(in [BELT_BLOCK_LEN]byte, out *[BELT_BLOCK_LEN]byte, ks [BELT_KEY_SCHED_LEN]byte) {
    var a, b, c, d, e uint32
    var i int

    a = getu32(in[0:])
    b = getu32(in[4:])
    c = getu32(in[8:])
    d = getu32(in[12:])

    for i = 0; i < 8; i++ {
        var key uint32
        var j = uint32(7 - i)

        key = getu32(ks[4*KIdx[j][6]:])
        b ^= G(a + key, 5)

        key = getu32(ks[4*KIdx[j][5]:])
        c ^= G(d + key, 21)

        key = getu32(ks[4*KIdx[j][4]:])
        a = uint32(a - G(b + key, 13))

        key = getu32(ks[4*KIdx[j][3]:])
        e = G(b + c + key, 21) ^ (j + 1)

        b += e
        c = c - e

        key = getu32(ks[4*KIdx[j][2]:])
        d += G(c + key, 13)

        key = getu32(ks[4*KIdx[j][1]:])
        b ^= G(a + key, 21)

        key = getu32(ks[4*KIdx[j][0]:])
        c ^= G(d + key, 5)

        a, b = b, a
        c, d = d, c
        a, d = d, a
    }

    putu32(out[0:], c)
    putu32(out[4:], a)
    putu32(out[8:], d)
    putu32(out[12:], b)
}

/* BELT-HASH primitives */
func sigma1Xor(x [2 * BELT_BLOCK_LEN]byte, h [2 * BELT_BLOCK_LEN]byte, s *[BELT_BLOCK_LEN]byte, use_xor bool) {
    var tmp1 [BELT_BLOCK_LEN]byte
    var i int

    for i = 0; i < (BELT_BLOCK_LEN / 2); i++ {
        tmp1[i] = (h[i] ^ h[i + BELT_BLOCK_LEN])
        tmp1[i + (BELT_BLOCK_LEN / 2)] = (h[i + (BELT_BLOCK_LEN / 2)] ^ h[i + BELT_BLOCK_LEN + (BELT_BLOCK_LEN / 2)])
    }

    if use_xor {
        var tmp2 [BELT_BLOCK_LEN]byte

        belt_encrypt(tmp1, &tmp2, x)

        for i = 0; i < (BELT_BLOCK_LEN / 2); i++ {
            s[i] ^= (tmp1[i] ^ tmp2[i])
            s[i + (BELT_BLOCK_LEN / 2)] ^= (tmp1[i + (BELT_BLOCK_LEN / 2)] ^ tmp2[i + (BELT_BLOCK_LEN / 2)])
        }
    } else {
        belt_encrypt(tmp1, s, x)

        for i = 0; i < (BELT_BLOCK_LEN / 2); i++ {
            s[i] ^= tmp1[i]
            s[i + (BELT_BLOCK_LEN / 2)] ^= tmp1[i + (BELT_BLOCK_LEN / 2)]
        }
    }
}

func sigma2(x [2 * BELT_BLOCK_LEN]byte, h [2 * BELT_BLOCK_LEN]byte, result *[2 * BELT_BLOCK_LEN]byte) {
    var teta [BELT_KEY_SCHED_LEN]byte
    var tmp [BELT_BLOCK_LEN]byte
    var i int

    /* Copy the beginning of h for later in case it is lost */
    copy(tmp[:], h[:BELT_BLOCK_LEN])

    var tmpTeta [BELT_BLOCK_LEN]byte
    sigma1Xor(x, h, &tmpTeta, false)

    copy(tmp[:], tmpTeta[:])
    copy(teta[BELT_BLOCK_LEN:], h[BELT_BLOCK_LEN:])

    var tmpX [BELT_BLOCK_LEN]byte
    var tmpResult [BELT_BLOCK_LEN]byte

    copy(tmpX[:], x[:])
    copy(tmpResult[:], result[:])

    belt_encrypt(tmpX, &tmpResult, teta)
    copy(result[:], tmpResult[:])
    for i = 0; i < BELT_BLOCK_LEN; i++ {
        result[i]  ^= x[i]
        teta[i]    ^= 0xff
        teta[i + BELT_BLOCK_LEN] = tmp[i]
    }

    copy(tmpX[:], x[BELT_BLOCK_LEN:])
    copy(tmpResult[:], result[BELT_BLOCK_LEN:])

    belt_encrypt(tmpX, &tmpResult, teta)
    copy(result[BELT_BLOCK_LEN:], tmpResult[:])

    for i = 0; i < (BELT_BLOCK_LEN / 2); i++ {
        result[i + BELT_BLOCK_LEN] ^= x[i + BELT_BLOCK_LEN]
        result[i + BELT_BLOCK_LEN + (BELT_BLOCK_LEN / 2)] ^= x[i + BELT_BLOCK_LEN + (BELT_BLOCK_LEN / 2)]
    }
}

func hashProcess(x [2 * BELT_BLOCK_LEN]byte, h *[2 * BELT_BLOCK_LEN]byte, s *[BELT_BLOCK_LEN]byte) {
    sigma1Xor(x, *h, s, true)

    sigma2(x, *h, h)
}

func hashFinalize(s [2 * BELT_BLOCK_LEN]byte, h [2 * BELT_BLOCK_LEN]byte, res *[2 * BELT_BLOCK_LEN]byte) {
    sigma2(s, h, res)
}
