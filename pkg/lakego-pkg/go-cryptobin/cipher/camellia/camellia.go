package camellia

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// Package camellia is an implementation of the CAMELLIA encryption algorithm
// This is an unoptimized version based on the description in RFC 3713.
// References:
//   http://en.wikipedia.org/wiki/Camellia_%28cipher%29
//   https://info.isl.ntt.co.jp/crypt/eng/camellia/

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/camellia: invalid key size " + strconv.Itoa(int(k))
}

type camelliaCipher struct {
    kw   [5]uint64
    k    [25]uint64
    ke   [7]uint64
    klen int
}

// New creates and returns a new cipher.Block.
// The key argument should be 16, 24, or 32 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
    klen := len(key)
    switch klen {
        default:
            return nil, KeySizeError(klen)
        case 16, 24, 32:
            break
    }

    c := new(camelliaCipher)
    c.expandKey(key)

    return c, nil
}

func (this *camelliaCipher) BlockSize() int {
    return BlockSize
}

func (this *camelliaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/camellia: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/camellia: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/camellia: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *camelliaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/camellia: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/camellia: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/camellia: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *camelliaCipher) encrypt(dst, src []byte) {
    d1 := getu64(src[0:])
    d2 := getu64(src[8:])

    d1 ^= this.kw[1]
    d2 ^= this.kw[2]

    d2 = d2 ^ f(d1, this.k[1])
    d1 = d1 ^ f(d2, this.k[2])
    d2 = d2 ^ f(d1, this.k[3])
    d1 = d1 ^ f(d2, this.k[4])
    d2 = d2 ^ f(d1, this.k[5])
    d1 = d1 ^ f(d2, this.k[6])

    d1 = fl(d1, this.ke[1])
    d2 = flinv(d2, this.ke[2])

    d2 = d2 ^ f(d1, this.k[7])
    d1 = d1 ^ f(d2, this.k[8])
    d2 = d2 ^ f(d1, this.k[9])
    d1 = d1 ^ f(d2, this.k[10])
    d2 = d2 ^ f(d1, this.k[11])
    d1 = d1 ^ f(d2, this.k[12])

    d1 = fl(d1, this.ke[3])
    d2 = flinv(d2, this.ke[4])

    d2 = d2 ^ f(d1, this.k[13])
    d1 = d1 ^ f(d2, this.k[14])
    d2 = d2 ^ f(d1, this.k[15])
    d1 = d1 ^ f(d2, this.k[16])
    d2 = d2 ^ f(d1, this.k[17])
    d1 = d1 ^ f(d2, this.k[18])

    if this.klen > 16 {
        // 24 or 32

        d1 = fl(d1, this.ke[5])
        d2 = flinv(d2, this.ke[6])

        d2 = d2 ^ f(d1, this.k[19])
        d1 = d1 ^ f(d2, this.k[20])
        d2 = d2 ^ f(d1, this.k[21])
        d1 = d1 ^ f(d2, this.k[22])
        d2 = d2 ^ f(d1, this.k[23])
        d1 = d1 ^ f(d2, this.k[24])
    }

    d2 = d2 ^ this.kw[3]
    d1 = d1 ^ this.kw[4]

    putu64(dst[0:], d2)
    putu64(dst[8:], d1)
}

func (this *camelliaCipher) decrypt(dst, src []byte) {
    d2 := getu64(src[0:])
    d1 := getu64(src[8:])

    d1 = d1 ^ this.kw[4]
    d2 = d2 ^ this.kw[3]

    if this.klen > 16 {
        // 24 or 32

        d1 = d1 ^ f(d2, this.k[24])
        d2 = d2 ^ f(d1, this.k[23])
        d1 = d1 ^ f(d2, this.k[22])
        d2 = d2 ^ f(d1, this.k[21])
        d1 = d1 ^ f(d2, this.k[20])
        d2 = d2 ^ f(d1, this.k[19])

        d2 = fl(d2, this.ke[6])
        d1 = flinv(d1, this.ke[5])
    }

    d1 = d1 ^ f(d2, this.k[18])
    d2 = d2 ^ f(d1, this.k[17])
    d1 = d1 ^ f(d2, this.k[16])
    d2 = d2 ^ f(d1, this.k[15])
    d1 = d1 ^ f(d2, this.k[14])
    d2 = d2 ^ f(d1, this.k[13])

    d2 = fl(d2, this.ke[4])
    d1 = flinv(d1, this.ke[3])

    d1 = d1 ^ f(d2, this.k[12])
    d2 = d2 ^ f(d1, this.k[11])
    d1 = d1 ^ f(d2, this.k[10])
    d2 = d2 ^ f(d1, this.k[9])
    d1 = d1 ^ f(d2, this.k[8])
    d2 = d2 ^ f(d1, this.k[7])

    d2 = fl(d2, this.ke[2])
    d1 = flinv(d1, this.ke[1])

    d1 = d1 ^ f(d2, this.k[6])
    d2 = d2 ^ f(d1, this.k[5])
    d1 = d1 ^ f(d2, this.k[4])
    d2 = d2 ^ f(d1, this.k[3])
    d1 = d1 ^ f(d2, this.k[2])
    d2 = d2 ^ f(d1, this.k[1])

    d2 ^= this.kw[2]
    d1 ^= this.kw[1]

    putu64(dst[0:], d1)
    putu64(dst[8:], d2)
}

func (this *camelliaCipher) expandKey(key []byte) {
    var d1, d2 uint64

    var kl [2]uint64
    var kr [2]uint64
    var ka [2]uint64
    var kb [2]uint64

    klen := len(key)

    kl[0] = getu64(key[0:])
    kl[1] = getu64(key[8:])

    switch klen {
        case 24:
            kr[0] = getu64(key[16:])
            kr[1] = ^kr[0]
        case 32:
            kr[0] = getu64(key[16:])
            kr[1] = getu64(key[24:])
    }

    d1 = (kl[0] ^ kr[0])
    d2 = (kl[1] ^ kr[1])

    d2 = d2 ^ f(d1, sigma1)
    d1 = d1 ^ f(d2, sigma2)

    d1 = d1 ^ (kl[0])
    d2 = d2 ^ (kl[1])
    d2 = d2 ^ f(d1, sigma3)
    d1 = d1 ^ f(d2, sigma4)
    ka[0] = d1
    ka[1] = d2
    d1 = (ka[0] ^ kr[0])
    d2 = (ka[1] ^ kr[1])
    d2 = d2 ^ f(d1, sigma5)
    d1 = d1 ^ f(d2, sigma6)
    kb[0] = d1
    kb[1] = d2

    this.klen = klen

    if klen == 16 {

        this.kw[1], this.kw[2] = rotl128(kl, 0)

        this.k[1], this.k[2] = rotl128(ka, 0)
        this.k[3], this.k[4] = rotl128(kl, 15)
        this.k[5], this.k[6] = rotl128(ka, 15)

        this.ke[1], this.ke[2] = rotl128(ka, 30)

        this.k[7], this.k[8] = rotl128(kl, 45)
        this.k[9], _ = rotl128(ka, 45)
        _, this.k[10] = rotl128(kl, 60)
        this.k[11], this.k[12] = rotl128(ka, 60)

        this.ke[3], this.ke[4] = rotl128(kl, 77)

        this.k[13], this.k[14] = rotl128(kl, 94)
        this.k[15], this.k[16] = rotl128(ka, 94)
        this.k[17], this.k[18] = rotl128(kl, 111)

        this.kw[3], this.kw[4] = rotl128(ka, 111)

    } else {
        // 24 or 32

        this.kw[1], this.kw[2] = rotl128(kl, 0)

        this.k[1], this.k[2] = rotl128(kb, 0)
        this.k[3], this.k[4] = rotl128(kr, 15)
        this.k[5], this.k[6] = rotl128(ka, 15)

        this.ke[1], this.ke[2] = rotl128(kr, 30)

        this.k[7], this.k[8] = rotl128(kb, 30)
        this.k[9], this.k[10] = rotl128(kl, 45)
        this.k[11], this.k[12] = rotl128(ka, 45)

        this.ke[3], this.ke[4] = rotl128(kl, 60)

        this.k[13], this.k[14] = rotl128(kr, 60)
        this.k[15], this.k[16] = rotl128(kb, 60)
        this.k[17], this.k[18] = rotl128(kl, 77)

        this.ke[5], this.ke[6] = rotl128(ka, 77)

        this.k[19], this.k[20] = rotl128(kr, 94)
        this.k[21], this.k[22] = rotl128(ka, 94)
        this.k[23], this.k[24] = rotl128(kl, 111)

        this.kw[3], this.kw[4] = rotl128(kb, 111)
    }
}
