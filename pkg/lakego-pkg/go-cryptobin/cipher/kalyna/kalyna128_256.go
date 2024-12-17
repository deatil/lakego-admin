package kalyna

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize128_256 = 16

type kalynaCipher128_256 struct {
   erk [32]uint64
   drk [32]uint64
}

// NewCipher128_256 creates and returns a new cipher.Block.
func NewCipher128_256(key []byte) (cipher.Block, error) {
    keylen := len(key)
    if keylen != 32 {
        return nil, KeySizeError(keylen)
    }

    c := new(kalynaCipher128_256)
    c.expandKey(key)

    return c, nil
}

func (this *kalynaCipher128_256) BlockSize() int {
    return BlockSize128_256
}

func (this *kalynaCipher128_256) Encrypt(dst, src []byte) {
    if len(src) < BlockSize128_256 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize128_256 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize128_256], src[:BlockSize128_256]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *kalynaCipher128_256) Decrypt(dst, src []byte) {
    if len(src) < BlockSize128_256 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize128_256 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize128_256], src[:BlockSize128_256]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *kalynaCipher128_256) encrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 2), make([]uint64, 2)

    ins := bytesToUint64s(in)

    rk := this.erk[:]

    addkey128(ins, t1, rk)

    G128(t1, t2, rk[2:]) // 1
    G128(t2, t1, rk[4:]) // 2
    G128(t1, t2, rk[6:]) // 3
    G128(t2, t1, rk[8:]) // 4
    G128(t1, t2, rk[10:]) // 5
    G128(t2, t1, rk[12:]) // 6
    G128(t1, t2, rk[14:]) // 7
    G128(t2, t1, rk[16:]) // 8
    G128(t1, t2, rk[18:]) // 9
    G128(t2, t1, rk[20:]) // 10
    G128(t1, t2, rk[22:]) // 11
    G128(t2, t1, rk[24:]) // 12
    G128(t1, t2, rk[26:]) // 13
    GL128(t2, t1, rk[28:]) // 14

    ct := uint64sToBytes(t1)
    copy(out, ct)
}

func (this *kalynaCipher128_256) decrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 2), make([]uint64, 2)

    ins := bytesToUint64s(in)

    rk := this.drk[:]

    subkey128(ins, t1, rk[28:])

    IMC128(t1)
    IG128(t1, t2, rk[26:])
    IG128(t2, t1, rk[24:])
    IG128(t1, t2, rk[22:])
    IG128(t2, t1, rk[20:])
    IG128(t1, t2, rk[18:])
    IG128(t2, t1, rk[16:])
    IG128(t1, t2, rk[14:])
    IG128(t2, t1, rk[12:])
    IG128(t1, t2, rk[10:])
    IG128(t2, t1, rk[8:])
    IG128(t1, t2, rk[6:])
    IG128(t2, t1, rk[4:])
    IG128(t1, t2, rk[2:])
    IGL128(t2, t1, rk[0:])

    pt := uint64sToBytes(t1)
    copy(out, pt)
}

func (this *kalynaCipher128_256) expandKey(key []byte) {
    var ks, ksc, t1, t2, ka, ko, k []uint64
    ks = make([]uint64, 2)
    ksc = make([]uint64, 2)
    t1 = make([]uint64, 2)
    t2 = make([]uint64, 2)
    ka = make([]uint64, 2)
    ko = make([]uint64, 2)
    k = make([]uint64, 4)

    keys := bytesToUint64s(key)

    t1[0] = (128 + 256 + 64) / 64

    copy(ka, keys[:2])
    copy(ko, keys[2:])

    addkey128(t1, t2, ka)
    G128(t2, t1, ko)
    GL128(t1, t2, ka)
    G0128(t2, ks)

    var constant uint64 = 0x0001000100010001

    rk := make([]uint64, 32)

    // round 0
    copy(k, keys[:4])
    add_constant128(ks, ksc, constant)
    addkey128(k, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[0:], ksc)
    make_odd_key128(rk[0:], rk[2:])

    // round 2
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k[2:], t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[4:], ksc)
    make_odd_key128(rk[4:], rk[6:])

    // round 4
    swap_block256(k)
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[8:], ksc)
    make_odd_key128(rk[8:], rk[10:])

    // round 6
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k[2:], t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[12:], ksc)
    make_odd_key128(rk[12:], rk[14:])

    // round 8
    swap_block256(k)
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[16:], ksc)
    make_odd_key128(rk[16:], rk[18:])

    // round 10
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k[2:], t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[20:], ksc)
    make_odd_key128(rk[20:], rk[22:])

    // round 12
    swap_block256(k)
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k, t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[24:], ksc)
    make_odd_key128(rk[24:], rk[26:])

    // round 14
    constant <<= 1
    add_constant128(ks, ksc, constant)
    addkey128(k[2:], t2, ksc)
    G128(t2, t1, ksc)
    GL128(t1, rk[28:], ksc)

    copy(this.erk[:], rk)

    for i := 26; i > 0; i -= 2 {
        IMC128(rk[i:])
    }

    copy(this.drk[:], rk)
}
