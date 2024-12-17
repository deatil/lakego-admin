package cast

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/cast: invalid key size " + strconv.Itoa(int(k))
}

type castCipher struct {
    km []uint32
    kr []byte
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 20, 24, 28, 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(castCipher)
    c.expandKey(key)

    return c, nil
}

func (this *castCipher) BlockSize() int {
    return BlockSize
}

func (this *castCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/cast: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/cast: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/cast: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *castCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/cast: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/cast: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/cast: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *castCipher) encrypt(dst, src []byte) {
    blk := bytesToUint32s(src)

    a, b, c, d := blk[0], blk[1], blk[2], blk[3]

    kr := this.kr
    km := this.km

    var i int
    for i = 0; i < 24; i += 4 {
        c ^= f1(d, kr[i + 0], km[i + 0])
        b ^= f2(c, kr[i + 1], km[i + 1])
        a ^= f3(b, kr[i + 2], km[i + 2])
        d ^= f1(a, kr[i + 3], km[i + 3])
    }

    for i = 28; i < 52; i += 4 {
        d ^= f1(a, kr[i - 1], km[i - 1])
        a ^= f3(b, kr[i - 2], km[i - 2])
        b ^= f2(c, kr[i - 3], km[i - 3])
        c ^= f1(d, kr[i - 4], km[i - 4])
    }

    dstBytes := uint32sToBytes([4]uint32{a, b, c, d})

    copy(dst, dstBytes[:])
}

func (this *castCipher) decrypt(dst, src []byte) {
    blk := bytesToUint32s(src)

    a, b, c, d := blk[0], blk[1], blk[2], blk[3]

    kr := this.kr
    km := this.km

    var i int
    for i = 44; i > 20; i -= 4 {
        c ^= f1(d, kr[i + 0], km[i + 0])
        b ^= f2(c, kr[i + 1], km[i + 1])
        a ^= f3(b, kr[i + 2], km[i + 2])
        d ^= f1(a, kr[i + 3], km[i + 3])
    }

    for i = 24; i > 0; i -= 4 {
        d ^= f1(a, kr[i - 1], km[i - 1])
        a ^= f3(b, kr[i - 2], km[i - 2])
        b ^= f2(c, kr[i - 3], km[i - 3])
        c ^= f1(d, kr[i - 4], km[i - 4])
    }

    dstBytes := uint32sToBytes([4]uint32{a, b, c, d})

    copy(dst, dstBytes[:])
}

func (this *castCipher) expandKey(key []byte) {
    var keys [8]uint32

    inKey := keyToUint32s(key)
    for i := 0; i < len(inKey); i++ {
        keys[i] = inKey[i]
    }

    this.km = make([]uint32, 48)
    this.kr = make([]byte, 48)

    keyInit(keys, this.km, this.kr)
}
