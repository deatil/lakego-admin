package camellia

import (
    "sync"
    "strconv"
    "math/bits"
    "crypto/cipher"
    "encoding/binary"
)

// Package camellia is an implementation of the CAMELLIA encryption algorithm
// This is an unoptimized version based on the description in RFC 3713.
// References:
//   http://en.wikipedia.org/wiki/Camellia_%28cipher%29
//   https://info.isl.ntt.co.jp/crypt/eng/camellia/

const BlockSize = 16

const (
    sigma1 = 0xA09E667F3BCC908B
    sigma2 = 0xB67AE8584CAA73B2
    sigma3 = 0xC6EF372FE94F82BE
    sigma4 = 0x54FF53A5F1D36F1C
    sigma5 = 0x10E527FADE682D1D
    sigma6 = 0xB05688C2B3E6C1FD
)

var once sync.Once

func initAll() {
    // initialize other sboxes
    for i := range sbox1 {
        sbox2[i] = bits.RotateLeft8(sbox1[i], 1)
        sbox3[i] = bits.RotateLeft8(sbox1[i], 7)
        sbox4[i] = sbox1[bits.RotateLeft8(uint8(i), 1)]
    }
}

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/camellia: invalid key size " + strconv.Itoa(int(k))
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

    once.Do(initAll)

    var d1, d2 uint64

    var kl [2]uint64
    var kr [2]uint64
    var ka [2]uint64
    var kb [2]uint64

    kl[0] = binary.BigEndian.Uint64(key[0:])
    kl[1] = binary.BigEndian.Uint64(key[8:])

    switch klen {
        case 24:
            kr[0] = binary.BigEndian.Uint64(key[16:])
            kr[1] = ^kr[0]
        case 32:
            kr[0] = binary.BigEndian.Uint64(key[16:])
            kr[1] = binary.BigEndian.Uint64(key[24:])
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

    c := new(camelliaCipher)

    c.klen = klen

    if klen == 16 {

        c.kw[1], c.kw[2] = rotl128(kl, 0)

        c.k[1], c.k[2] = rotl128(ka, 0)
        c.k[3], c.k[4] = rotl128(kl, 15)
        c.k[5], c.k[6] = rotl128(ka, 15)

        c.ke[1], c.ke[2] = rotl128(ka, 30)

        c.k[7], c.k[8] = rotl128(kl, 45)
        c.k[9], _ = rotl128(ka, 45)
        _, c.k[10] = rotl128(kl, 60)
        c.k[11], c.k[12] = rotl128(ka, 60)

        c.ke[3], c.ke[4] = rotl128(kl, 77)

        c.k[13], c.k[14] = rotl128(kl, 94)
        c.k[15], c.k[16] = rotl128(ka, 94)
        c.k[17], c.k[18] = rotl128(kl, 111)

        c.kw[3], c.kw[4] = rotl128(ka, 111)

    } else {
        // 24 or 32

        c.kw[1], c.kw[2] = rotl128(kl, 0)

        c.k[1], c.k[2] = rotl128(kb, 0)
        c.k[3], c.k[4] = rotl128(kr, 15)
        c.k[5], c.k[6] = rotl128(ka, 15)

        c.ke[1], c.ke[2] = rotl128(kr, 30)

        c.k[7], c.k[8] = rotl128(kb, 30)
        c.k[9], c.k[10] = rotl128(kl, 45)
        c.k[11], c.k[12] = rotl128(ka, 45)

        c.ke[3], c.ke[4] = rotl128(kl, 60)

        c.k[13], c.k[14] = rotl128(kr, 60)
        c.k[15], c.k[16] = rotl128(kb, 60)
        c.k[17], c.k[18] = rotl128(kl, 77)

        c.ke[5], c.ke[6] = rotl128(ka, 77)

        c.k[19], c.k[20] = rotl128(kr, 94)
        c.k[21], c.k[22] = rotl128(ka, 94)
        c.k[23], c.k[24] = rotl128(kl, 111)

        c.kw[3], c.kw[4] = rotl128(kb, 111)
    }

    return c, nil
}

func (c *camelliaCipher) BlockSize() int {
    return BlockSize
}

func (c *camelliaCipher) Encrypt(dst, src []byte) {
    d1 := binary.BigEndian.Uint64(src[0:])
    d2 := binary.BigEndian.Uint64(src[8:])

    d1 ^= c.kw[1]
    d2 ^= c.kw[2]

    d2 = d2 ^ f(d1, c.k[1])
    d1 = d1 ^ f(d2, c.k[2])
    d2 = d2 ^ f(d1, c.k[3])
    d1 = d1 ^ f(d2, c.k[4])
    d2 = d2 ^ f(d1, c.k[5])
    d1 = d1 ^ f(d2, c.k[6])

    d1 = fl(d1, c.ke[1])
    d2 = flinv(d2, c.ke[2])

    d2 = d2 ^ f(d1, c.k[7])
    d1 = d1 ^ f(d2, c.k[8])
    d2 = d2 ^ f(d1, c.k[9])
    d1 = d1 ^ f(d2, c.k[10])
    d2 = d2 ^ f(d1, c.k[11])
    d1 = d1 ^ f(d2, c.k[12])

    d1 = fl(d1, c.ke[3])
    d2 = flinv(d2, c.ke[4])

    d2 = d2 ^ f(d1, c.k[13])
    d1 = d1 ^ f(d2, c.k[14])
    d2 = d2 ^ f(d1, c.k[15])
    d1 = d1 ^ f(d2, c.k[16])
    d2 = d2 ^ f(d1, c.k[17])
    d1 = d1 ^ f(d2, c.k[18])

    if c.klen > 16 {
        // 24 or 32

        d1 = fl(d1, c.ke[5])
        d2 = flinv(d2, c.ke[6])

        d2 = d2 ^ f(d1, c.k[19])
        d1 = d1 ^ f(d2, c.k[20])
        d2 = d2 ^ f(d1, c.k[21])
        d1 = d1 ^ f(d2, c.k[22])
        d2 = d2 ^ f(d1, c.k[23])
        d1 = d1 ^ f(d2, c.k[24])
    }

    d2 = d2 ^ c.kw[3]
    d1 = d1 ^ c.kw[4]

    binary.BigEndian.PutUint64(dst[0:], d2)
    binary.BigEndian.PutUint64(dst[8:], d1)
}

func (c *camelliaCipher) Decrypt(dst, src []byte) {

    d2 := binary.BigEndian.Uint64(src[0:])
    d1 := binary.BigEndian.Uint64(src[8:])

    d1 = d1 ^ c.kw[4]
    d2 = d2 ^ c.kw[3]

    if c.klen > 16 {
        // 24 or 32

        d1 = d1 ^ f(d2, c.k[24])
        d2 = d2 ^ f(d1, c.k[23])
        d1 = d1 ^ f(d2, c.k[22])
        d2 = d2 ^ f(d1, c.k[21])
        d1 = d1 ^ f(d2, c.k[20])
        d2 = d2 ^ f(d1, c.k[19])

        d2 = fl(d2, c.ke[6])
        d1 = flinv(d1, c.ke[5])
    }

    d1 = d1 ^ f(d2, c.k[18])
    d2 = d2 ^ f(d1, c.k[17])
    d1 = d1 ^ f(d2, c.k[16])
    d2 = d2 ^ f(d1, c.k[15])
    d1 = d1 ^ f(d2, c.k[14])
    d2 = d2 ^ f(d1, c.k[13])

    d2 = fl(d2, c.ke[4])
    d1 = flinv(d1, c.ke[3])

    d1 = d1 ^ f(d2, c.k[12])
    d2 = d2 ^ f(d1, c.k[11])
    d1 = d1 ^ f(d2, c.k[10])
    d2 = d2 ^ f(d1, c.k[9])
    d1 = d1 ^ f(d2, c.k[8])
    d2 = d2 ^ f(d1, c.k[7])

    d2 = fl(d2, c.ke[2])
    d1 = flinv(d1, c.ke[1])

    d1 = d1 ^ f(d2, c.k[6])
    d2 = d2 ^ f(d1, c.k[5])
    d1 = d1 ^ f(d2, c.k[4])
    d2 = d2 ^ f(d1, c.k[3])
    d1 = d1 ^ f(d2, c.k[2])
    d2 = d2 ^ f(d1, c.k[1])

    d2 ^= c.kw[2]
    d1 ^= c.kw[1]

    binary.BigEndian.PutUint64(dst[0:], d1)
    binary.BigEndian.PutUint64(dst[8:], d2)
}
