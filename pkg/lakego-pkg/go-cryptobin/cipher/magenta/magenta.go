package magenta

import (
    "fmt"
    "sync"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("cryptobin/magenta: invalid key size %d", int(k))
}

var once sync.Once

func initAll() {
    init_tab()
}

type magentaCipher struct {
    l_key [16]uint32
    k_len uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    once.Do(initAll)

    c := new(magentaCipher)

    keyUint32s := bytesToUint32s(key)
    c.expandKey(keyUint32s, uint32(k) * 8)

    return c, nil
}

func (this *magentaCipher) BlockSize() int {
    return BlockSize
}

func (this *magentaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/magenta: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/magenta: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/magenta: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.encrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *magentaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/magenta: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/magenta: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/magenta: invalid buffer overlap")
    }

    encSrc := bytesToUint32s(src)
    encDst := make([]uint32, len(encSrc))

    this.decrypt(encDst, encSrc)

    resBytes := uint32sToBytes(encDst)
    copy(dst, resBytes)
}

func (this *magentaCipher) expandKey(in_key []uint32, key_len uint32) {
    this.k_len = (key_len + 63) / 64;

    var l_key [16]uint32

    switch this.k_len {
        case 2:
            l_key[ 0] = in_key[0]
            l_key[ 1] = in_key[1]
            l_key[ 2] = in_key[0]
            l_key[ 3] = in_key[1]
            l_key[ 4] = in_key[2]
            l_key[ 5] = in_key[3]
            l_key[ 6] = in_key[2]
            l_key[ 7] = in_key[3]
            l_key[ 8] = in_key[0]
            l_key[ 9] = in_key[1]
            l_key[10] = in_key[0]
            l_key[11] = in_key[1]
        case 3:
            l_key[ 0] = in_key[0]
            l_key[ 1] = in_key[1]
            l_key[ 2] = in_key[2]
            l_key[ 3] = in_key[3]
            l_key[ 4] = in_key[4]
            l_key[ 5] = in_key[5]
            l_key[ 6] = in_key[4]
            l_key[ 7] = in_key[5]
            l_key[ 8] = in_key[2]
            l_key[ 9] = in_key[3]
            l_key[10] = in_key[0]
            l_key[11] = in_key[1]
        case 4:
            l_key[ 0] = in_key[0]
            l_key[ 1] = in_key[1]
            l_key[ 2] = in_key[2]
            l_key[ 3] = in_key[3]
            l_key[ 4] = in_key[4]
            l_key[ 5] = in_key[5]
            l_key[ 6] = in_key[6]
            l_key[ 7] = in_key[7]
            l_key[ 8] = in_key[6]
            l_key[ 9] = in_key[7]
            l_key[10] = in_key[4]
            l_key[11] = in_key[5]
            l_key[12] = in_key[2]
            l_key[13] = in_key[3]
            l_key[14] = in_key[0]
            l_key[15] = in_key[1]
    }

    this.l_key = l_key
}

func (this *magentaCipher) encrypt(out_blk []uint32, in_blk []uint32) {
    var blk, tt [4]uint32

    l_key := this.l_key

    blk[0] = in_blk[0]
    blk[1] = in_blk[1]
    blk[2] = in_blk[2]
    blk[3] = in_blk[3]

    r_fun(tt, blk[0:], blk[2:], l_key[0:])
    r_fun(tt, blk[2:], blk[0:], l_key[2:])

    r_fun(tt, blk[0:], blk[2:], l_key[4:])
    r_fun(tt, blk[2:], blk[0:], l_key[6:])

    r_fun(tt, blk[0:], blk[2:], l_key[8:])
    r_fun(tt, blk[2:], blk[0:], l_key[10:])

    if this.k_len == 4 {
        r_fun(tt, blk[0:], blk[2:], l_key[12:])
        r_fun(tt, blk[2:], blk[0:], l_key[14:])
    }

    out_blk[0] = blk[0]
    out_blk[1] = blk[1]
    out_blk[2] = blk[2]
    out_blk[3] = blk[3]
}

func (this *magentaCipher) decrypt(out_blk []uint32, in_blk []uint32) {
    var blk, tt [4]uint32

    l_key := this.l_key

    blk[2] = in_blk[0]
    blk[3] = in_blk[1]
    blk[0] = in_blk[2]
    blk[1] = in_blk[3]

    r_fun(tt, blk[0:], blk[2:], l_key[0:])
    r_fun(tt, blk[2:], blk[0:], l_key[2:])

    r_fun(tt, blk[0:], blk[2:], l_key[4:])
    r_fun(tt, blk[2:], blk[0:], l_key[6:])

    r_fun(tt, blk[0:], blk[2:], l_key[8:])
    r_fun(tt, blk[2:], blk[0:], l_key[10:])

    if this.k_len == 4 {
        r_fun(tt, blk[0:], blk[2:], l_key[12:])
        r_fun(tt, blk[2:], blk[0:], l_key[14:])
    }

    out_blk[2] = blk[0]
    out_blk[3] = blk[1]
    out_blk[0] = blk[2]
    out_blk[1] = blk[3]
}
