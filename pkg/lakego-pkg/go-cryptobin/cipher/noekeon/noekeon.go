package noekeon

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/noekeon: invalid key size %d", int(k))
}

type noekeonCipher struct {
    K, dK []uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(noekeonCipher)
    c.expandKey(key)

    return c, nil
}

func (this *noekeonCipher) BlockSize() int {
    return BlockSize
}

func (this *noekeonCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/noekeon: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/noekeon: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/noekeon: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *noekeonCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/noekeon: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/noekeon: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/noekeon: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *noekeonCipher) expandKey(in_key []byte) {
    this.K = make([]uint32, 4)
    this.dK = make([]uint32, 4)

    K := bytesToUint32s(in_key)
    copy(this.K[0:], K)

    dK := bytesToUint32s(in_key)

    kTHETA(&dK[0], &dK[1], &dK[2], &dK[3])

    copy(this.dK[0:], dK)
}

func (this *noekeonCipher) encryptROUND(a, b, c, d *uint32, i int32) {
    (*a) ^= RC[i]

    THETA(this.K[:], a, b, c, d)

    PI1(a, b, c, d)
    GAMMA(a, b, c, d)
    PI2(a, b, c, d)
}

func (this *noekeonCipher) encrypt(dst []uint32, src []uint32) {
    var a, b, c, d uint32
    var r int32

    a = src[0]
    b = src[1]
    c = src[2]
    d = src[3]

    for r = 0; r < 16; r++ {
        this.encryptROUND(&a, &b, &c, &d, r)
    }

    a ^= RC[16]

    THETA(this.K[:], &a, &b, &c, &d)

    dst[0] = a
    dst[1] = b
    dst[2] = c
    dst[3] = d
}

func (this *noekeonCipher) decryptROUND(a, b, c, d *uint32, i int32) {
    THETA(this.dK[:], a, b, c, d)

    (*a) ^= RC[i]

    PI1(a, b, c, d)
    GAMMA(a, b, c, d)
    PI2(a, b, c, d)
}

func (this *noekeonCipher) decrypt(dst []uint32, src []uint32) {
    var a, b, c, d uint32
    var r int32

    a = src[0]
    b = src[1]
    c = src[2]
    d = src[3]

    for r = 16; r > 0; r-- {
        this.decryptROUND(&a, &b, &c, &d, r)
    }

    THETA(this.dK[:], &a, &b, &c, &d)

    a ^= RC[0]

    dst[0] = a
    dst[1] = b
    dst[2] = c
    dst[3] = d
}
