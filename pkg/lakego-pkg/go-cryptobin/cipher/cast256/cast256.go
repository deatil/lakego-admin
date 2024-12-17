package cast256

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/cast256: invalid key size " + strconv.Itoa(int(k))
}

type cast256Cipher struct {
    l_key [96]uint32
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

    c := new(cast256Cipher)
    c.expandKey(key)

    return c, nil
}

func (this *cast256Cipher) BlockSize() int {
    return BlockSize
}

func (this *cast256Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/cast256: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/cast256: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/cast256: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *cast256Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/cast256: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/cast256: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/cast256: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *cast256Cipher) encrypt(dst, src []byte) {
    blk := bytesToUint32s(src)

    var i uint32
    for i = 0; i < 6; i++ {
        f_rnd(&blk, i * 8, this.l_key)
    }

    for i = 6; i < 12; i++ {
        i_rnd(&blk, i * 8, this.l_key)
    }

    dstBytes := uint32sToBytes(blk)

    copy(dst, dstBytes[:])
}

func (this *cast256Cipher) decrypt(dst, src []byte) {
    blk := bytesToUint32s(src)

    var i uint32
    for i = 11; i > 5; i-- {
        f_rnd(&blk, i * 8, this.l_key)
    }

    for i = 6; i > 0; i-- {
        i_rnd(&blk, (i-1) * 8, this.l_key)
    }

    dstBytes := uint32sToBytes(blk)

    copy(dst, dstBytes[:])
}

func (this *cast256Cipher) expandKey(key []byte) {
    var i, j, cm, cr uint32
    var lk, tm, tr [8]uint32

    inKey := keyToUint32s(key)

    for i = 0; i < uint32(len(inKey)); i++ {
        lk[i] = inKey[i]
    }

    cm = 0x5a827999
    cr = 19

    for i = 0; i < 96; i += 8 {
        for j = 0; j < 8; j++ {
            tm[j] = cm
            cm += 0x6ed9eba1
            tr[j] = cr
            cr += 17
        }

        k_rnd(&lk, tr, tm)

        for j = 0; j < 8; j++ {
            tm[j] = cm
            cm += 0x6ed9eba1
            tr[j] = cr
            cr += 17
        }

        k_rnd(&lk, tr, tm)

        this.l_key[i + 0] = lk[0]
        this.l_key[i + 1] = lk[2]
        this.l_key[i + 2] = lk[4]
        this.l_key[i + 3] = lk[6]
        this.l_key[i + 4] = lk[7]
        this.l_key[i + 5] = lk[5]
        this.l_key[i + 6] = lk[3]
        this.l_key[i + 7] = lk[1]
    }
}
