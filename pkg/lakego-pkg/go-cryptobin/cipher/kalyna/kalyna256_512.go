package kalyna

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize256_512 = 32

type kalynaCipher256_512 struct {
   erk [80]uint64
   drk [80]uint64
}

// NewCipher256_512 creates and returns a new cipher.Block.
func NewCipher256_512(key []byte) (cipher.Block, error) {
    keylen := len(key)
    if keylen != 64 {
        return nil, KeySizeError(keylen)
    }

    c := new(kalynaCipher256_512)
    c.expandKey(key)

    return c, nil
}

func (this *kalynaCipher256_512) BlockSize() int {
    return BlockSize256_512
}

func (this *kalynaCipher256_512) Encrypt(dst, src []byte) {
    if len(src) < BlockSize256_512 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize256_512 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize256_512], src[:BlockSize256_512]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *kalynaCipher256_512) Decrypt(dst, src []byte) {
    if len(src) < BlockSize256_512 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize256_512 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize256_512], src[:BlockSize256_512]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *kalynaCipher256_512) encrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 4), make([]uint64, 4)

    ins := bytesToUint64s(in)

    rk := this.erk[:]

    addkey256(ins, t1, rk)

    G256(t1, t2, rk[4:]) // 1
    G256(t2, t1, rk[8:]) // 2
    G256(t1, t2, rk[12:]) // 3
    G256(t2, t1, rk[16:]) // 4
    G256(t1, t2, rk[20:]) // 5
    G256(t2, t1, rk[24:]) // 6
    G256(t1, t2, rk[28:]) // 7
    G256(t2, t1, rk[32:]) // 8
    G256(t1, t2, rk[36:]) // 9
    G256(t2, t1, rk[40:]) // 10
    G256(t1, t2, rk[44:]) // 11
    G256(t2, t1, rk[48:]) // 12
    G256(t1, t2, rk[52:]) // 13
    G256(t2, t1, rk[56:]) // 14
    G256(t1, t2, rk[60:]) // 15
    G256(t2, t1, rk[64:]) // 16
    G256(t1, t2, rk[68:]) // 17
    GL256(t2, t1, rk[72:]) // 18

    ct := uint64sToBytes(t1)
    copy(out, ct)
}

func (this *kalynaCipher256_512) decrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 4), make([]uint64, 4)

    ins := bytesToUint64s(in)

    rk := this.drk[:]

    subkey256(ins, t1, rk[72:])

    IMC256(t1)
    IG256(t1, t2, rk[68:])
    IG256(t2, t1, rk[64:])
    IG256(t1, t2, rk[60:])
    IG256(t2, t1, rk[56:])
    IG256(t1, t2, rk[52:])
    IG256(t2, t1, rk[48:])
    IG256(t1, t2, rk[44:])
    IG256(t2, t1, rk[40:])
    IG256(t1, t2, rk[36:])
    IG256(t2, t1, rk[32:])
    IG256(t1, t2, rk[28:])
    IG256(t2, t1, rk[24:])
    IG256(t1, t2, rk[20:])
    IG256(t2, t1, rk[16:])
    IG256(t1, t2, rk[12:])
    IG256(t2, t1, rk[8:])
    IG256(t1, t2, rk[4:])
    IGL256(t2, t1, rk[0:])

    pt := uint64sToBytes(t1)
    copy(out, pt)
}

func (this *kalynaCipher256_512) expandKey(key []byte) {
    var ks, ksc, t1, t2, ka, ko, k []uint64
    ks = make([]uint64, 4)
    ksc = make([]uint64, 4)
    t1 = make([]uint64, 4)
    t2 = make([]uint64, 4)
    ka = make([]uint64, 4)
    ko = make([]uint64, 4)
    k = make([]uint64, 8)

    keys := bytesToUint64s(key)

    t1[0] = (512 + 256 + 64) / 64

    copy(ka, keys[:4])
    copy(ko, keys[4:])

    addkey256(t1, t2, ka)
    G256(t2, t1, ko)
    GL256(t1, t2, ka)
    G0256(t2, ks)

    var constant uint64 = 0x0001000100010001

    rk := make([]uint64, 80)

    // round 0
    copy(k, keys[:8])
    add_constant256(ks, ksc, constant)
    addkey256(k, t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[0:], ksc)
    make_odd_key256(rk[0:], rk[4:])

    // round 2
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k[4:], t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[8:], ksc)
    make_odd_key256(rk[8:], rk[12:])

    // round 4
    swap_block(k)
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k, t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[16:], ksc)
    make_odd_key256(rk[16:], rk[20:])

    // round 6
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k[4:], t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[24:], ksc)
    make_odd_key256(rk[24:], rk[28:])

    // round 8
    swap_block(k)
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k, t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[32:], ksc)
    make_odd_key256(rk[32:], rk[36:])

    // round 10
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k[4:], t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[40:], ksc)
    make_odd_key256(rk[40:], rk[44:])

    // round 12
    swap_block(k)
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k, t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[48:], ksc)
    make_odd_key256(rk[48:], rk[52:])

    // round 14
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k[4:], t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[56:], ksc)
    make_odd_key256(rk[56:], rk[60:])

    // round 16
    swap_block(k)
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k, t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[64:], ksc)
    make_odd_key256(rk[64:], rk[68:])

    // round 18
    constant <<= 1
    add_constant256(ks, ksc, constant)
    addkey256(k[4:], t2, ksc)
    G256(t2, t1, ksc)
    GL256(t1, rk[72:], ksc)

    copy(this.erk[:], rk)

    for i := 68; i > 0; i -= 4 {
        IMC256(rk[i:])
    }

    copy(this.drk[:], rk)
}
