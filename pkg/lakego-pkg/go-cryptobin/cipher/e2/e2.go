package e2

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/e2: invalid key size %d", int(k))
}

type e2Cipher struct {
    l_key [72]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(e2Cipher)
    c.expandKey(key)

    return c, nil
}

func (this *e2Cipher) BlockSize() int {
    return BlockSize
}

func (this *e2Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/e2: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/e2: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/e2: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *e2Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/e2: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/e2: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/e2: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *e2Cipher) expandKey(key []byte) {
    var lk [8]uint32
    var v [2]uint32
    var lout [8]uint32
    var i, j, k, w uint32

    in_key := bytesToUint32s(key)
    key_len := uint32(len(key)) * 8

    v[0] = bswap(v_0)
    v[1] = bswap(v_1)

    lk[0] = io_swap(in_key[0])
    lk[1] = io_swap(in_key[1])
    lk[2] = io_swap(in_key[2])
    lk[3] = io_swap(in_key[3])

    var lk_4, lk_5 uint32
    if key_len > 128 {
        lk_4 = in_key[4]
    } else {
        lk_4 = k2_0
    }

    if key_len > 128 {
        lk_5 = in_key[5]
    } else {
        lk_5 = k2_1
    }

    lk[4] = io_swap(lk_4)
    lk[5] = io_swap(lk_5)

    var lk_6, lk_7 uint32
    if key_len > 192 {
        lk_6 = in_key[6]
    } else {
        lk_6 = k3_0
    }

    if key_len > 192 {
        lk_7 = in_key[7]
    } else {
        lk_7 = k3_1
    }

    lk[6] = io_swap(lk_6)
    lk[7] = io_swap(lk_7)

    lout, v = g_fun(lk, lout, v)

    l_keyBytes := uint32sToBytes(this.l_key[:])

    for i = 0; i < 8; i++ {
        lout, v = g_fun(lk, lout, v)

        loutBytes := uint32sToBytes(lout[:])

        for j = 0; j < 4; j++ {
            k = 2 * (48 - 16 * j + 2 * (i / 2) - i % 2)

            l_keyBytes[k + 3]   = loutBytes[j];
            l_keyBytes[k + 2]   = loutBytes[j + 16];

            l_keyBytes[k + 19]  = loutBytes[j +  8];
            l_keyBytes[k + 18]  = loutBytes[j + 24];

            l_keyBytes[k + 131] = loutBytes[j +  4];
            l_keyBytes[k + 130] = loutBytes[j + 20];

            l_keyBytes[k + 147] = loutBytes[j + 12];
            l_keyBytes[k + 146] = loutBytes[j + 28];
        }
    }

    l_key := bytesToUint32s(l_keyBytes)

    for i = 52; i < 60; i++ {
        l_key[i] |= 1
        l_key[i + 12] = mod_inv(l_key[i])
    }

    for i = 0; i < 48; i += 4 {
        bp2_fun(&w, &l_key[i], &l_key[i + 1])
    }

    copy(this.l_key[0:], l_key)
}

func (this *e2Cipher) encrypt(dst []uint32, src []uint32) {
    var a, b, c, d, p, q, r, s, u, v uint32
    var out_blk [4]uint32

    l_key := this.l_key

    p = io_swap(src[0])
    q = io_swap(src[1])
    r = io_swap(src[2])
    s = io_swap(src[3])

    p ^= l_key[48]
    q ^= l_key[49]
    r ^= l_key[50]
    s ^= l_key[51]

    p *= l_key[52]
    q *= l_key[53]
    r *= l_key[54]
    s *= l_key[55]

    bp_fun(&u, &v, &a, &b, &c, &d, p, q, r, s)

    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[0:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[4:])
    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[8:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[12:])
    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[16:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[20:])
    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[24:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[28:])
    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[32:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[36:])
    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[40:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[44:])

    ibp_fun(&u, &v, &p, &q, &r, &s, a, b, c, d)

    p *= l_key[68]
    q *= l_key[69]
    r *= l_key[70]
    s *= l_key[71]
    p ^= l_key[60]
    q ^= l_key[61]
    r ^= l_key[62]
    s ^= l_key[63]

    out_blk[0] = io_swap(p)
    out_blk[1] = io_swap(q)
    out_blk[2] = io_swap(r)
    out_blk[3] = io_swap(s)

    copy(dst[0:], out_blk[:])
}

func (this *e2Cipher) decrypt(dst []uint32, src []uint32) {
    var a, b, c, d, p, q, r, s, u, v uint32
    var out_blk [4]uint32

    l_key := this.l_key

    p = io_swap(src[0])
    q = io_swap(src[1])
    r = io_swap(src[2])
    s = io_swap(src[3])

    p ^= l_key[60]
    q ^= l_key[61]
    r ^= l_key[62]
    s ^= l_key[63]

    p *= l_key[56]
    q *= l_key[57]
    r *= l_key[58]
    s *= l_key[59]

    bp_fun(&u, &v, &a, &b, &c, &d, p, q, r, s)

    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[44:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[40:])

    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[36:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[32:])

    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[28:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[24:])

    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[20:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[16:])

    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[12:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[8:])

    f_fun(&p, &q, &r, &s, &u, &v, &a, &b, c, d, l_key[4:])
    f_fun(&p, &q, &r, &s, &u, &v, &c, &d, a, b, l_key[0:])

    ibp_fun(&u, &v, &p, &q, &r, &s, a, b, c, d)

    p *= l_key[64]
    q *= l_key[65]
    r *= l_key[66]
    s *= l_key[67]

    p ^= l_key[48]
    q ^= l_key[49]
    r ^= l_key[50]
    s ^= l_key[51]

    out_blk[0] = io_swap(p)
    out_blk[1] = io_swap(q)
    out_blk[2] = io_swap(r)
    out_blk[3] = io_swap(s)

    copy(dst[0:], out_blk[:])
}
