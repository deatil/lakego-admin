package lea

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/lea: invalid key size %d", int(k))
}

type leaCipher struct {
    erk [][6]uint32
    drk [][6]uint32
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the LEA key,
// either 16, 24, or 32 bytes to select LEA-128, LEA-192, or LEA-256.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(leaCipher)
    c.expandKey(key)

    return c, nil
}

func (this *leaCipher) BlockSize() int {
    return BlockSize
}

func (this *leaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/lea: invalid block size %d (src)", len(src)))
    }

    if len(dst) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/lea: invalid block size %d (dst)", len(dst)))
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/lea: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *leaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/lea: invalid block size %d (src)", len(src)))
    }

    if len(dst) < BlockSize {
        panic(fmt.Sprintf("go-cryptobin/lea: invalid block size %d (dst)", len(dst)))
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/lea: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *leaCipher) encrypt(dst, src []byte) {
    res := crypt(src, this.erk, true)

    copy(dst, res[:])
}

func (this *leaCipher) decrypt(dst, src []byte) {
    res := crypt(src, this.drk, false)

    copy(dst, res[:])
}

func (this *leaCipher) expandKey(key []byte) {
    this.erk = roundKey(key, true)
    this.drk = roundKey(key, false)
}
