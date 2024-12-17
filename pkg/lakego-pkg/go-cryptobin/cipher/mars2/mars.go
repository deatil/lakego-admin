package mars2

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/mars: invalid key size " + strconv.Itoa(int(k))
}

type marsCipher struct {
    key [40]uint32
}

// NewCipher creates and returns a new cipher.Block.
// The mars is other version.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(marsCipher)
    c.expandKey(key)

    return c, nil
}

func (this *marsCipher) BlockSize() int {
    return BlockSize
}

func (this *marsCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/mars: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/mars: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/mars: invalid buffer overlap")
    }

    in_blk := bytesToUint32s(src)

    encBlock := encrypt(in_blk, this.key)

    encBytes := uint32sToBytes(encBlock)

    copy(dst, encBytes[:])
}

func (this *marsCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/mars: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/mars: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/mars: invalid buffer overlap")
    }

    in_blk := bytesToUint32s(src)

    decBlock := decrypt(in_blk, this.key);

    decBytes := uint32sToBytes(decBlock)

    copy(dst, decBytes[:])
}

func (this *marsCipher) expandKey(key []byte) {
    inKey := keyToUint32s(key)
    k := len(key)

    this.key = expandKey(inKey, uint32(k) * 8)
}
