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

// =================

type zuc256Cipher struct {
    state *Zuc256State
}

// New256Cipher creates and returns a new cipher.Stream.
func New256Cipher(key []byte, iv []byte) (cipher.Stream, error) {
    return New256CipherWithMacbits(key, iv, 0)
}

// New256CipherWithMacbits creates and returns a new cipher.Stream.
func New256CipherWithMacbits(key []byte, iv []byte, macbits int32) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(zuc256Cipher)
    c.state = NewZuc256StateWithMacbits(key, iv, macbits)

    return c, nil
}

func (this *zuc256Cipher) XORKeyStream(dst, src []byte) {
    this.state.Encrypt(dst, src)
}

// =================

type eeaCipher struct {
    state *ZucState
}

// NewEEACipher creates and returns a new cipher.Stream.
func NewEEACipher(key []byte, count, bearer, direction uint32) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 16:
            break
        default:
            return nil, KeySizeError(k)
    }

    state := new(ZucState)
    state.SetEeaKey(key, count, bearer, direction)

    c := new(zucCipher)
    c.state = state

    return c, nil
}

func (this *eeaCipher) XORKeyStream(dst, src []byte) {
    this.state.Encrypt(dst, src)
}
