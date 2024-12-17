package magenta

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/magenta: invalid key size %d", int(k))
}

type magentaCipher struct {
    lkey [16]uint32
    klen uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(magentaCipher)
    c.expandKey(key)

    return c, nil
}

func (this *magentaCipher) BlockSize() int {
    return BlockSize
}

func (this *magentaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/magenta: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/magenta: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/magenta: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *magentaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/magenta: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/magenta: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/magenta: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *magentaCipher) encrypt(out []uint32, in []uint32) {
    var blk, tt [4]uint32

    lkey := this.lkey

    blk[0] = in[0]
    blk[1] = in[1]
    blk[2] = in[2]
    blk[3] = in[3]

    r(&tt, blk[0:], blk[2:], lkey[0:])
    r(&tt, blk[2:], blk[0:], lkey[2:])

    r(&tt, blk[0:], blk[2:], lkey[4:])
    r(&tt, blk[2:], blk[0:], lkey[6:])

    r(&tt, blk[0:], blk[2:], lkey[8:])
    r(&tt, blk[2:], blk[0:], lkey[10:])

    if this.klen == 4 {
        r(&tt, blk[0:], blk[2:], lkey[12:])
        r(&tt, blk[2:], blk[0:], lkey[14:])
    }

    out[0] = blk[0]
    out[1] = blk[1]
    out[2] = blk[2]
    out[3] = blk[3]
}

func (this *magentaCipher) decrypt(out []uint32, in []uint32) {
    var blk, tt [4]uint32

    lkey := this.lkey

    blk[2] = in[0]
    blk[3] = in[1]
    blk[0] = in[2]
    blk[1] = in[3]

    r(&tt, blk[0:], blk[2:], lkey[0:])
    r(&tt, blk[2:], blk[0:], lkey[2:])

    r(&tt, blk[0:], blk[2:], lkey[4:])
    r(&tt, blk[2:], blk[0:], lkey[6:])

    r(&tt, blk[0:], blk[2:], lkey[8:])
    r(&tt, blk[2:], blk[0:], lkey[10:])

    if this.klen == 4 {
        r(&tt, blk[0:], blk[2:], lkey[12:])
        r(&tt, blk[2:], blk[0:], lkey[14:])
    }

    out[2] = blk[0]
    out[3] = blk[1]
    out[0] = blk[2]
    out[1] = blk[3]
}

func (this *magentaCipher) expandKey(key []byte) {
    inKey := bytesToUint32s(key)
    keyLen := uint32(len(key)) * 8

    this.klen = (keyLen + 63) / 64;

    var lkey [16]uint32

    switch this.klen {
        case 2:
            lkey[ 0] = inKey[0]
            lkey[ 1] = inKey[1]
            lkey[ 2] = inKey[0]
            lkey[ 3] = inKey[1]
            lkey[ 4] = inKey[2]
            lkey[ 5] = inKey[3]
            lkey[ 6] = inKey[2]
            lkey[ 7] = inKey[3]
            lkey[ 8] = inKey[0]
            lkey[ 9] = inKey[1]
            lkey[10] = inKey[0]
            lkey[11] = inKey[1]
        case 3:
            lkey[ 0] = inKey[0]
            lkey[ 1] = inKey[1]
            lkey[ 2] = inKey[2]
            lkey[ 3] = inKey[3]
            lkey[ 4] = inKey[4]
            lkey[ 5] = inKey[5]
            lkey[ 6] = inKey[4]
            lkey[ 7] = inKey[5]
            lkey[ 8] = inKey[2]
            lkey[ 9] = inKey[3]
            lkey[10] = inKey[0]
            lkey[11] = inKey[1]
        case 4:
            lkey[ 0] = inKey[0]
            lkey[ 1] = inKey[1]
            lkey[ 2] = inKey[2]
            lkey[ 3] = inKey[3]
            lkey[ 4] = inKey[4]
            lkey[ 5] = inKey[5]
            lkey[ 6] = inKey[6]
            lkey[ 7] = inKey[7]
            lkey[ 8] = inKey[6]
            lkey[ 9] = inKey[7]
            lkey[10] = inKey[4]
            lkey[11] = inKey[5]
            lkey[12] = inKey[2]
            lkey[13] = inKey[3]
            lkey[14] = inKey[0]
            lkey[15] = inKey[1]
    }

    this.lkey = lkey
}
