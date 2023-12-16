package zuc

import (
    "crypto/cipher"
)

type zucCipher struct {
    state *ZucState
}

// NewCipher creates and returns a new cipher.Stream.
func NewCipher(key []byte, iv []byte) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 16:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(zucCipher)
    c.state = NewZucState(key, iv)

    return c, nil
}

func (this *zucCipher) XORKeyStream(dst, src []byte) {
    this.state.Encrypt(dst, src)
}
