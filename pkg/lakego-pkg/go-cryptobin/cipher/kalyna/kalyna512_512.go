package kalyna

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize512_512 = 64

type kalynaCipher512_512 struct {
   erk [152]uint64
   drk [152]uint64
}

// NewCipher512_512 creates and returns a new cipher.Block.
func NewCipher512_512(key []byte) (cipher.Block, error) {
    keylen := len(key)
    if keylen != 64 {
        return nil, KeySizeError(keylen)
    }

    c := new(kalynaCipher512_512)
    c.expandKey(key)

    return c, nil
}

func (this *kalynaCipher512_512) BlockSize() int {
    return BlockSize512_512
}

func (this *kalynaCipher512_512) Encrypt(dst, src []byte) {
    if len(src) < BlockSize512_512 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize512_512 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize512_512], src[:BlockSize512_512]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *kalynaCipher512_512) Decrypt(dst, src []byte) {
    if len(src) < BlockSize512_512 {
        panic("go-cryptobin/kalyna: input not full block")
    }

    if len(dst) < BlockSize512_512 {
        panic("go-cryptobin/kalyna: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize512_512], src[:BlockSize512_512]) {
        panic("go-cryptobin/kalyna: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *kalynaCipher512_512) encrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 8), make([]uint64, 8)

    ins := bytesToUint64s(in)

    rk := this.erk[:]

    addkey(ins, t1, rk)

    G(t1, t2, rk[8:]) // 1
    G(t2, t1, rk[16:]) // 2
    G(t1, t2, rk[24:]) // 3
    G(t2, t1, rk[32:]) // 4
    G(t1, t2, rk[40:]) // 5
    G(t2, t1, rk[48:]) // 6
    G(t1, t2, rk[56:]) // 7
    G(t2, t1, rk[64:]) // 8
    G(t1, t2, rk[72:]) // 9
    G(t2, t1, rk[80:]) // 10
    G(t1, t2, rk[88:]) // 11
    G(t2, t1, rk[96:]) // 12
    G(t1, t2, rk[104:]) // 13
    G(t2, t1, rk[112:]) // 14
    G(t1, t2, rk[120:]) // 15
    G(t2, t1, rk[128:]) // 16
    G(t1, t2, rk[136:]) // 17
    GL(t2, t1, rk[144:]) // 18

    ct := uint64sToBytes(t1)
    copy(out, ct)
}

func (this *kalynaCipher512_512) decrypt(out []byte, in []byte) {
    var t1, t2 []uint64
    t1, t2 = make([]uint64, 8), make([]uint64, 8)

    ins := bytesToUint64s(in)

    rk := this.drk[:]

    subkey(ins, t1, rk[144:])

    IMC(t1)
    IG(t1, t2, rk[136:])
    IG(t2, t1, rk[128:])
    IG(t1, t2, rk[120:])
    IG(t2, t1, rk[112:])
    IG(t1, t2, rk[104:])
    IG(t2, t1, rk[96:])
    IG(t1, t2, rk[88:])
    IG(t2, t1, rk[80:])
    IG(t1, t2, rk[72:])
    IG(t2, t1, rk[64:])
    IG(t1, t2, rk[56:])
    IG(t2, t1, rk[48:])
    IG(t1, t2, rk[40:])
    IG(t2, t1, rk[32:])
    IG(t1, t2, rk[24:])
    IG(t2, t1, rk[16:])
    IG(t1, t2, rk[8:])
    IGL(t2, t1, rk[0:])

    pt := uint64sToBytes(t1)
    copy(out, pt)
}

func (this *kalynaCipher512_512) expandKey(key []byte) {
    var ks, ksc, t1, t2, k []uint64
    ks = make([]uint64, 8)
    ksc = make([]uint64, 8)
    t2 = make([]uint64, 8)
    k = make([]uint64, 8)

    t1 = make([]uint64, 8)
    t1[0] = (512 + 512 + 64) / 64

    keys := bytesToUint64s(key)

    addkey(t1, t2, keys)
    G(t2, t1, keys)
    GL(t1, t2, keys)
    G0(t2, ks)

    var constant uint64 = 0x0001000100010001;

    rk := make([]uint64, 152)

    // round 0
    copy(k, keys[:8])
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[0:], ksc)
    make_odd_key(rk[0:], rk[8:])

    // round 2
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[16:], ksc)
    make_odd_key(rk[16:], rk[24:])

    // round 4
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[32:], ksc)
    make_odd_key(rk[32:], rk[40:])

    // round 6
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[48:], ksc)
    make_odd_key(rk[48:], rk[56:])

    // round 8
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[64:], ksc)
    make_odd_key(rk[64:], rk[72:])

    // round 10
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[80:], ksc)
    make_odd_key(rk[80:], rk[88:])

    // round 12
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[96:], ksc)
    make_odd_key(rk[96:], rk[104:])

    // round 14
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[112:], ksc)
    make_odd_key(rk[112:], rk[120:])

    // round 16
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[128:], ksc)
    make_odd_key(rk[128:], rk[136:]);

    // round 18
    swap_block(k)
    constant <<= 1
    add_constant(ks, ksc, constant)
    addkey(k, t2, ksc)
    G(t2, t1, ksc)
    GL(t1, rk[144:], ksc)

    copy(this.erk[:], rk)

    for i := 136; i > 0; i -= 8 {
        IMC(rk[i:])
    }

    copy(this.drk[:], rk)
}
