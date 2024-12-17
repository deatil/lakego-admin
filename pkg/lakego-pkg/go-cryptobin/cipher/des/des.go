package des

import (
    "strconv"
    "crypto/des"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// The DES block size in bytes.
const BlockSize = des.BlockSize

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/twoDes: invalid key size " + strconv.Itoa(int(k))
}

type twoDESCipher struct {
    cipher cipher.Block
}

// NewTwoDESCipher creates and returns a new cipher.Block.
func NewTwoDESCipher(key []byte) (cipher.Block, error) {
    if len(key) != 16 {
        return nil, KeySizeError(len(key))
    }

    key = append(key, key[:8]...)

    cip, err := des.NewTripleDESCipher(key)
    if err != nil {
        return nil, err
    }

    c := new(twoDESCipher)
    c.cipher = cip

    return c, nil
}

func (this *twoDESCipher) BlockSize() int {
    return BlockSize
}

func (this *twoDESCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/twoDes: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/twoDes: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/twoDes: invalid buffer overlap")
    }

    this.cipher.Encrypt(dst, src)
}

func (this *twoDESCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/twoDes: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/twoDes: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/twoDes: invalid buffer overlap")
    }

    this.cipher.Decrypt(dst, src)
}
