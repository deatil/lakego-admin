package kalyna

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize128_128 = 16

type kalynaCipher128_128 struct {
   erk [24]uint64
   drk [24]uint64
}

// NewCipher128_128 creates and returns a new cipher.Block.
func NewCipher128_128(key []byte) (cipher.Block, error) {
    keylen := len(key)
    if keylen != 16 {
        return nil, KeySizeError(keylen)
    }

    c := new(kalynaCipher128_128)
    c.expandKey(key)

    return c, nil
}

func (this *kalynaCipher128_128) BlockSize() int {
    return BlockSize128_128
}

func (this *kalynaCipher128_128) Encrypt(dst, src []byte) {
    if len(src) < BlockSize128_128 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize128_128 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize128_128], src[:BlockSize128_128]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *kalynaCipher128_128) Decrypt(dst, src []byte) {
    if len(src) < BlockSize128_128 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize128_128 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize128_128], src[:BlockSize128_128]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *kalynaCipher128_128) encrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 2), make([]uint64, 2)

    ins := bytesToUint64s(in)

    rk := this.erk[:]

    addkey128(ins, t1, rk)

    var i int
    for i = 2; i < 18; i += 4 {
        G128(t1, t2, rk[i    :]) // i + 1
        G128(t2, t1, rk[i + 2:]) // i + 2
    }

    G128(t1, t2, rk[18:]) // 9
    GL128(t2, t1, rk[20:]) // 10

    ct := uint64sToBytes(t1)
    copy(out, ct)
}

func (this *kalynaCipher128_128) decrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 2), make([]uint64, 2)

    ins := bytesToUint64s(in)

    rk := this.drk[:]

    subkey128(ins, t1, rk[20:])

    IMC128(t1)

    var i int
    for i = 18; i > 2; i -= 4 {
        IG128(t1, t2, rk[i    :])
        IG128(t2, t1, rk[i - 2:])
    }

    IG128(t1, t2, rk[2:])
    IGL128(t2, t1, rk[0:])

    pt := uint64sToBytes(t1)
    copy(out, pt)
}

func (this *kalynaCipher128_128) expandKey(key []byte) {
    var ks, ksc, t1, t2, k, kswapped []uint64
    ks = make([]uint64, 2)
    ksc = make([]uint64, 2)
    t1 = make([]uint64, 2)
    t2 = make([]uint64, 2)
    k = make([]uint64, 2)
    kswapped = make([]uint64, 2)

    keys := bytesToUint64s(key)

    t1[0] = (128 + 128 + 64) / 64

    addkey128(t1, t2, keys)
    G128(t2, t1, keys)
    GL128(t1, t2, keys)
    G0128(t2, ks)

    var constant uint64 = 0x0001000100010001

    rk := make([]uint64, 24)

    copy(k, keys[:2])
    kswapped[1] = k[0]
    kswapped[0] = k[1]

    // round 0
    add_constant128(ks, ksc, constant)
    addkey128(k, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[0:], ksc)
    make_odd_key128(rk[0:], rk[2:])

    // round 2
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(kswapped, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[4:], ksc)
    make_odd_key128(rk[4:], rk[6:])

    // round 4
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[8:], ksc)
    make_odd_key128(rk[8:], rk[10:])

    // round 6
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(kswapped, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[12:], ksc)
    make_odd_key128(rk[12:], rk[14:])

    // round 8
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[16:], ksc)
    make_odd_key128(rk[16:], rk[18:])

    // round 10
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(kswapped, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[20:], ksc)

    copy(this.erk[:], rk)

    for i := 18; i > 0; i -= 2 {
        IMC128(rk[i:])
    }

    copy(this.drk[:], rk)
}
