package gost

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/gost: invalid key size: " + strconv.Itoa(int(k))
}

type SboxSizeError int

func (k SboxSizeError) Error() string {
    return "go-cryptobin/gost: invalid sbox size: " + strconv.Itoa(int(k))
}

// GOST 28147-89 defines a block size of 64 bits
const BlockSize = 8

// Internal state of the GOST block cipher
type gostCipher struct {
    key []uint32 // Encryption key
    s   [][]byte // S-box provided as parameter
    k   [][]byte // Expanded s-box
}

// NewCipher creates and returns a new cipher.Block. The key argument
// should be the 32 byte GOST 28147-89 key. The sbox argument should be a
// 64 byte substitution table, represented as a two-dimensional array of 8 rows
// of 16 4-bit integers.
func NewCipher(key []byte, sbox [][]byte) (cipher.Block, error) {
    if len(key) != 32 {
        return nil, KeySizeError(len(key))
    }

    if len(sbox) != 8 {
        return nil, SboxSizeError(len(sbox))
    }

    for i := 0; i < len(sbox); i++ {
        if len(sbox[i]) != 16 {
            return nil, SboxSizeError(len(sbox[i]))
        }
    }

    c := new(gostCipher)
    c.expandKey(key, sbox)

    return c, nil
}

func (this *gostCipher) BlockSize() int {
    return BlockSize
}

func (this *gostCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/gost: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/gost: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/gost: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *gostCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/gost: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/gost: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/gost: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

// Encrypt one block from src into dst.
func (this *gostCipher) encrypt(dst, src []uint32) {
    n1, n2 := src[0], src[1]

    var j int

    // three rounds
    for i := 0; i < 3; i++ {
        for j = 0; j < 8; j++ {
            if j%2 == 0 {
                n2 = n2 ^ this.round(n1 + this.key[j])
            } else {
                n1 = n1 ^ this.round(n2 + this.key[j])
            }
        }
    }

    // last round
    for j = 7; j >= 0; j-- {
        if j%2 != 0 {
            n2 = n2 ^ this.round(n1 + this.key[j])
        } else {
            n1 = n1 ^ this.round(n2 + this.key[j])
        }
    }

    dst[0], dst[1] = n2, n1
}

// Decrypt one block from src into dst.
func (this *gostCipher) decrypt(dst, src []uint32) {
    n1, n2 := src[0], src[1]

    var j int

    // first round
    for j = 0; j < 8; j++ {
        if j%2 == 0 {
            n2 = n2 ^ this.round(n1 + this.key[j])
        } else {
            n1 = n1 ^ this.round(n2 + this.key[j])
        }
    }

    // three rounds
    for i := 0; i < 3; i++ {
        for j = 7; j >= 0; j-- {
            if j%2 != 0 {
                n2 = n2 ^ this.round(n1 + this.key[j])
            } else {
                n1 = n1 ^ this.round(n2 + this.key[j])
            }
        }
    }

    dst[0], dst[1] = n2, n1
}

// GOST block cipher round function
func (this *gostCipher) round(x uint32) uint32 {
    return cycle(x, this.k)
}

func (this *gostCipher) expandKey(key []byte, sbox [][]byte) {
    newKey := bytesToUint32s(key)
    kbox := sboxExpansion(sbox)

    this.key = newKey
    this.s = sbox
    this.k = kbox
}
