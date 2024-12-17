package kseed

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/kseed: invalid key size %d", int(k))
}

type kseedCipher struct {
    K, dK [32]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(kseedCipher)
    c.expandKey(key)

    return c, nil
}

func (this *kseedCipher) BlockSize() int {
    return BlockSize
}

func (this *kseedCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/kseed: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/kseed: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/kseed: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *kseedCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/kseed: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/kseed: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/kseed: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *kseedCipher) encrypt(dst []uint32, src []uint32) {
    var p [4]uint32

    p[0] = src[0]
    p[1] = src[1]
    p[2] = src[2]
    p[3] = src[3]

    rounds(p[:], this.K[:])

    dst[0] = p[2]
    dst[1] = p[3]
    dst[2] = p[0]
    dst[3] = p[1]
}

func (this *kseedCipher) decrypt(dst []uint32, src []uint32) {
    var p [4]uint32

    p[0] = src[0]
    p[1] = src[1]
    p[2] = src[2]
    p[3] = src[3]

    rounds(p[:], this.dK[:])

    dst[0] = p[2]
    dst[1] = p[3]
    dst[2] = p[0]
    dst[3] = p[1]
}

func (this *kseedCipher) expandKey(key []byte) {
    var i int32
    var tmp, k1, k2, k3, k4 uint32

    in_key := bytesToUint32s(key)

    k1 = in_key[0]
    k2 = in_key[1]
    k3 = in_key[2]
    k4 = in_key[3]

    for i = 0; i < 16; i++ {
        this.K[2*i+0] = G(k1 + k3 - KCi[i])
        this.K[2*i+1] = G(k2 - k4 + KCi[i])

        if (i&1) > 0 {
            tmp = k3
            k3 = ((k3 << 8) | (k4 >> 24)) & 0xFFFFFFFF
            k4 = ((k4 << 8) | (tmp >> 24)) & 0xFFFFFFFF
        } else {
            tmp = k1
            k1 = ((k1 >> 8) | (k2 << 24)) & 0xFFFFFFFF
            k2 = ((k2 >> 8) | (tmp << 24)) & 0xFFFFFFFF
        }

        this.dK[2*(15-i)+0] = this.K[2*i+0]
        this.dK[2*(15-i)+1] = this.K[2*i+1]
    }
}
