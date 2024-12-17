package crypton1

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/crypton1: invalid key size %d", int(k))
}

type crypton1Cipher struct {
    l_key [104]uint32
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

    c := new(crypton1Cipher)
    c.expandKey(key)

    return c, nil
}

func (this *crypton1Cipher) BlockSize() int {
    return BlockSize
}

func (this *crypton1Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/crypton1: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/crypton1: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/crypton1: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    dstBytes := uint32sToBytes(encDst)
    copy(dst, dstBytes[:])
}

func (this *crypton1Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/crypton1: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/crypton1: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/crypton1: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    dstBytes := uint32sToBytes(encDst)
    copy(dst, dstBytes[:])
}

func (this *crypton1Cipher) expandKey(key []byte) {
    var i, j, t0, t1 uint32
    var tu, tv [4]uint32
    var ek, dk [8]uint32

    var e_key [52]uint32
    var d_key [52]uint32

    l := len(key)
    key_len := uint32(l) * 8

    var in_key []uint32
    for l2 := 0; l2 < l; l2 += 4 {
        in_key = append(in_key, bytesToUint32(key[l2:]))
    }

    tu = [4]uint32{}
    tv = [4]uint32{}

    kk := (key_len + 63) / 64

    switch kk {
        case 4:
            tu[3] = Byte(in_key[6],0) |
                (Byte(in_key[6],2) <<  8) |
                (Byte(in_key[7],0) << 16) |
                (Byte(in_key[7],2) << 24)
            tv[3] = Byte(in_key[6],1) |
                (Byte(in_key[6],3) <<  8) |
                (Byte(in_key[7],1) << 16) |
                (Byte(in_key[7],3) << 24)
        case 3:
            tu[2] = Byte(in_key[4],0) |
                (Byte(in_key[4],2) <<  8) |
                (Byte(in_key[5],0) << 16) |
                (Byte(in_key[5],2) << 24)
            tv[2] = Byte(in_key[4],1) |
                (Byte(in_key[4],3) <<  8) |
                (Byte(in_key[5],1) << 16) |
                (Byte(in_key[5],3) << 24)
        case 2:
            tu[0] = Byte(in_key[0],0) |
                (Byte(in_key[0],2) <<  8) |
                (Byte(in_key[1],0) << 16) |
                (Byte(in_key[1],2) << 24)
            tv[0] = Byte(in_key[0],1) |
                (Byte(in_key[0],3) <<  8) |
                (Byte(in_key[1],1) << 16) |
                (Byte(in_key[1],3) << 24)

            tu[1] = Byte(in_key[2],0) |
                (Byte(in_key[2],2) <<  8) |
                (Byte(in_key[3],0) << 16) |
                (Byte(in_key[3],2) << 24)
            tv[1] = Byte(in_key[2],1) |
                (Byte(in_key[2],3) <<  8) |
                (Byte(in_key[3],1) << 16) |
                (Byte(in_key[3],3) << 24)
    }

    fr0(ek[0:], tu[0:], 0, 0)
    fr0(ek[0:], tu[0:], 1, 0)
    fr0(ek[0:], tu[0:], 2, 0)
    fr0(ek[0:], tu[0:], 3, 0)

    fr1(ek[4:], tv[0:], 0, 0)
    fr1(ek[4:], tv[0:], 1, 0)
    fr1(ek[4:], tv[0:], 2, 0)
    fr1(ek[4:], tv[0:], 3, 0)

    t0 = ek[0] ^ ek[1] ^ ek[2] ^ ek[3]
    t1 = ek[4] ^ ek[5] ^ ek[6] ^ ek[7]

    ek[0] ^= t1; ek[1] ^= t1
    ek[2] ^= t1; ek[3] ^= t1
    ek[4] ^= t0; ek[5] ^= t0
    ek[6] ^= t0; ek[7] ^= t0

    d_key[48] = ek[0] ^ ce[0]
    d_key[49] = ek[1] ^ ce[1]
    d_key[50] = ek[2] ^ ce[2]
    d_key[51] = ek[3] ^ ce[3]

    dk[0] = brotl(row_perm(rotr(ek[2], 16)), 4)
    dk[1] = brotl(row_perm(rotr(ek[3], 24)), 2)
    dk[2] = row_perm(rotr(ek[0], 24))
    dk[3] = brotl(row_perm(ek[1]), 2)

    dk[4] = brotl(row_perm(ek[7]), 6)
    dk[5] = brotl(row_perm(rotr(ek[4], 24)), 6)
    dk[6] = brotl(row_perm(ek[5]), 4)
    dk[7] = brotl(row_perm(rotr(ek[6], 16)), 4)

    for i, j = 0, 0; i < 13; i, j = i + 1, j + 4 {
        if (i & 1) > 0 {
            e_key[j]     = ek[4] ^ ce[j]
            e_key[j + 1] = ek[5] ^ ce[j + 1]
            e_key[j + 2] = ek[6] ^ ce[j + 2]
            e_key[j + 3] = ek[7] ^ ce[j + 3]

            t1 = ek[7]
            ek[7] = rotl(ek[6], 16)
            ek[6] = rotl(ek[5],  8)
            ek[5] = brotl(ek[4], 2)
            ek[4] = brotl(t1, 2)
        } else {
            e_key[j]     = ek[0] ^ ce[j]
            e_key[j + 1] = ek[1] ^ ce[j + 1]
            e_key[j + 2] = ek[2] ^ ce[j + 2]
            e_key[j + 3] = ek[3] ^ ce[j + 3]

            t1 = ek[0]
            ek[0] = rotl(ek[1], 24)
            ek[1] = rotl(ek[2], 16)
            ek[2] = brotl(ek[3], 6)
            ek[3] = brotl(t1, 6)
        }
    }

    for i, j = 0, 0; i < 12; i, j = i+1, j+4 {
        if (i & 1) > 0 {
            d_key[j]     = dk[4] ^ cd[j]
            d_key[j + 1] = dk[5] ^ cd[j + 1]
            d_key[j + 2] = dk[6] ^ cd[j + 2]
            d_key[j + 3] = dk[7] ^ cd[j + 3]

            t1 = dk[5]
            dk[5] = rotl(dk[6], 16)
            dk[6] = rotl(dk[7], 24)
            dk[7] = brotl(dk[4], 6)
            dk[4] = brotl(t1, 6)
        } else {
            d_key[j]     = dk[0] ^ cd[j]
            d_key[j + 1] = dk[1] ^ cd[j + 1]
            d_key[j + 2] = dk[2] ^ cd[j + 2]
            d_key[j + 3] = dk[3] ^ cd[j + 3]

            t1 = dk[2]
            dk[2] = rotl(dk[1],  8)
            dk[1] = rotl(dk[0], 16)
            dk[0] = brotl(dk[3], 2)
            dk[3] = brotl(t1, 2)
        }
    }

    e_key[48] = row_perm(rotr(e_key[48],16))
    e_key[49] = row_perm(rotr(e_key[49], 8))
    e_key[50] = row_perm(e_key[50])
    e_key[51] = row_perm(rotr(e_key[51],24))

    copy(this.l_key[0:], d_key[:])
    copy(this.l_key[52:], e_key[:])
};

func (this *crypton1Cipher) encrypt(out_blk []uint32, in_blk []uint32) {
    var b0, b1 [4]uint32

    e_key := this.l_key[52:]

    b0[0] = in_blk[0] ^ e_key[0]
    b0[1] = in_blk[1] ^ e_key[1]
    b0[2] = in_blk[2] ^ e_key[2]
    b0[3] = in_blk[3] ^ e_key[3]

    f0_rnd(b1[:], b0[:], e_key[ 4:])
    f1_rnd(b0[:], b1[:], e_key[ 8:])
    f0_rnd(b1[:], b0[:], e_key[12:])
    f1_rnd(b0[:], b1[:], e_key[16:])
    f0_rnd(b1[:], b0[:], e_key[20:])
    f1_rnd(b0[:], b1[:], e_key[24:])
    f0_rnd(b1[:], b0[:], e_key[28:])
    f1_rnd(b0[:], b1[:], e_key[32:])
    f0_rnd(b1[:], b0[:], e_key[36:])
    f1_rnd(b0[:], b1[:], e_key[40:])
    f0_rnd(b1[:], b0[:], e_key[44:])

    gamma_tau(b0[:], b1[:], 0)
    gamma_tau(b0[:], b1[:], 1)
    gamma_tau(b0[:], b1[:], 2)
    gamma_tau(b0[:], b1[:], 3)

    out_blk[0] = b0[0] ^ e_key[48]
    out_blk[1] = b0[1] ^ e_key[49]
    out_blk[2] = b0[2] ^ e_key[50]
    out_blk[3] = b0[3] ^ e_key[51]
}

func (this *crypton1Cipher) decrypt(out_blk []uint32, in_blk []uint32) {
    var b0, b1 [4]uint32

    d_key := this.l_key[0:52]

    b0[0] = in_blk[0] ^ d_key[0]
    b0[1] = in_blk[1] ^ d_key[1]
    b0[2] = in_blk[2] ^ d_key[2]
    b0[3] = in_blk[3] ^ d_key[3]

    f0_rnd(b1[:], b0[:], d_key[ 4:])
    f1_rnd(b0[:], b1[:], d_key[ 8:])
    f0_rnd(b1[:], b0[:], d_key[12:])
    f1_rnd(b0[:], b1[:], d_key[16:])
    f0_rnd(b1[:], b0[:], d_key[20:])
    f1_rnd(b0[:], b1[:], d_key[24:])
    f0_rnd(b1[:], b0[:], d_key[28:])
    f1_rnd(b0[:], b1[:], d_key[32:])
    f0_rnd(b1[:], b0[:], d_key[36:])
    f1_rnd(b0[:], b1[:], d_key[40:])
    f0_rnd(b1[:], b0[:], d_key[44:])

    gamma_tau(b0[:], b1[:], 0)
    gamma_tau(b0[:], b1[:], 1)
    gamma_tau(b0[:], b1[:], 2)
    gamma_tau(b0[:], b1[:], 3)

    out_blk[0] = b0[0] ^ d_key[48]
    out_blk[1] = b0[1] ^ d_key[49]
    out_blk[2] = b0[2] ^ d_key[50]
    out_blk[3] = b0[3] ^ d_key[51]
}
