package clefia

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/clefia: invalid key size %d", int(k))
}

type clefiaCipher struct {
    skey []byte
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

    c := new(clefiaCipher)
    c.expandKey(key)

    return c, nil
}

func (this *clefiaCipher) BlockSize() int {
    return BlockSize
}

func (this *clefiaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/clefia: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/clefia: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/clefia: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *clefiaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/clefia: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/clefia: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/clefia: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *clefiaCipher) encrypt(dst, src []byte) {
    var rk [8 * 26 + 16]byte /* 8 bytes x 26 rounds(max) + whitening keys */
    var r int32

    r = ClefiaKeySet(rk[:], this.skey, int32(len(this.skey)) * 8)
    ClefiaEncrypt(dst, src, rk[:], r)
}

func (this *clefiaCipher) decrypt(dst, src []byte) {
    var rk [8 * 26 + 16]byte /* 8 bytes x 26 rounds(max) + whitening keys */
    var r int32

    r = ClefiaKeySet(rk[:], this.skey, int32(len(this.skey)) * 8)
    ClefiaDecrypt(dst, src, rk[:], r)
}

func (this *clefiaCipher) expandKey(key []byte) {
    this.skey = make([]byte, len(key))
    copy(this.skey, key)
}
