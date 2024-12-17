package multi2

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/multi2: invalid key size %d", int(k))
}

type multi2Cipher struct {
    N int32
    uk [8]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte, rounds int32) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 40:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(multi2Cipher)
    c.expandKey(key, rounds)

    return c, nil
}

func (this *multi2Cipher) BlockSize() int {
    return BlockSize
}

func (this *multi2Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/multi2: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/multi2: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/multi2: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *multi2Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/multi2: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/multi2: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/multi2: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *multi2Cipher) expandKey(key []byte, num_rounds int32) {
    var sk [8]uint32
    var dk [2]uint32

    in_key := bytesToUint32s(key)

    this.N = num_rounds;

    copy(sk[0:], in_key[:8])
    copy(dk[0:], in_key[8:])

    setup(dk[:], sk[:], this.uk[:])
}

func (this *multi2Cipher) encrypt(dst []uint32, src []uint32) {
    var p [2]uint32

    p[0] = src[0]
    p[1] = src[1]

    encrypt(p[:], this.N, this.uk[:])

    dst[0] = p[0]
    dst[1] = p[1]
}

func (this *multi2Cipher) decrypt(dst []uint32, src []uint32) {
    var p [2]uint32

    p[0] = src[0]
    p[1] = src[1]

    decrypt(p[:], this.N, this.uk[:])

    dst[0] = p[0]
    dst[1] = p[1]
}
