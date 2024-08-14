package gcm

import (
    "crypto/cipher"
)

// cbcEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC encryption, like crypto/aes.
// NewCBCEncrypter will check for this interface and return the specific
// BlockMode if found.
type CBCEncAble interface {
    NewCBCEncrypter(iv []byte) cipher.BlockMode
}

// cbcDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC decryption, like crypto/aes.
// NewCBCDecrypter will check for this interface and return the specific
// BlockMode if found.
type CBCDecAble interface {
    NewCBCDecrypter(iv []byte) cipher.BlockMode
}

// gcmAble is an interface implemented by ciphers that have a specific optimized
// implementation of GCM, like crypto/aes. NewGCM will check for this interface
// and return the specific AEAD if found.
type GCMAble interface {
    NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
}

// ctrAble is an interface implemented by ciphers that have a specific optimized
// implementation of CTR, like crypto/aes. NewCTR will check for this interface
// and return the specific Stream if found.
type CTRAble interface {
    NewCTR(iv []byte) cipher.Stream
}

type Block interface {
    cipher.Block

    Encrypt4(dst, src []byte)
    Decrypt4(dst, src []byte)

    Encrypt8(dst, src []byte)
    Decrypt8(dst, src []byte)
}

func WrapCipher(b cipher.Block) Block {
    if kb, ok := b.(Block); ok {
        return kb
    }
    return &blockWrap{Block: b}
}

func NewCipher(newCipher func([]byte) (cipher.Block, error)) func([]byte) (cipher.Block, error) {
    return func(key []byte) (cipher.Block, error) {
        b, err := newCipher(key)
        if err != nil {
            return nil, err
        }
        return WrapCipher(b), nil
    }
}

type blockWrap struct {
    cipher.Block
}

var (
    _ cipher.Block = (*blockWrap)(nil)
    _ Block        = (*blockWrap)(nil)
)

func (b blockWrap) Encrypt4(dst, src []byte) {
    bs := b.BlockSize()
    b.Encrypt(dst[0*bs:1*bs], src[0*bs:1*bs])
    b.Encrypt(dst[1*bs:2*bs], src[1*bs:2*bs])
    b.Encrypt(dst[2*bs:3*bs], src[2*bs:3*bs])
    b.Encrypt(dst[3*bs:4*bs], src[3*bs:4*bs])
}

func (b blockWrap) Decrypt4(dst, src []byte) {
    bs := b.BlockSize()
    b.Decrypt(dst[0*bs:1*bs], src[0*bs:1*bs])
    b.Decrypt(dst[1*bs:2*bs], src[1*bs:2*bs])
    b.Decrypt(dst[2*bs:3*bs], src[2*bs:3*bs])
    b.Decrypt(dst[3*bs:4*bs], src[3*bs:4*bs])
}

func (b blockWrap) Encrypt8(dst, src []byte) {
    bs := b.BlockSize()
    b.Encrypt(dst[0*bs:1*bs], src[0*bs:1*bs])
    b.Encrypt(dst[1*bs:2*bs], src[1*bs:2*bs])
    b.Encrypt(dst[2*bs:3*bs], src[2*bs:3*bs])
    b.Encrypt(dst[3*bs:4*bs], src[3*bs:4*bs])
    b.Encrypt(dst[4*bs:5*bs], src[4*bs:5*bs])
    b.Encrypt(dst[5*bs:6*bs], src[5*bs:6*bs])
    b.Encrypt(dst[6*bs:7*bs], src[6*bs:7*bs])
    b.Encrypt(dst[7*bs:8*bs], src[7*bs:8*bs])
}

func (b blockWrap) Decrypt8(dst, src []byte) {
    bs := b.BlockSize()
    b.Decrypt(dst[0*bs:1*bs], src[0*bs:1*bs])
    b.Decrypt(dst[1*bs:2*bs], src[1*bs:2*bs])
    b.Decrypt(dst[2*bs:3*bs], src[2*bs:3*bs])
    b.Decrypt(dst[3*bs:4*bs], src[3*bs:4*bs])
    b.Decrypt(dst[4*bs:5*bs], src[4*bs:5*bs])
    b.Decrypt(dst[5*bs:6*bs], src[5*bs:6*bs])
    b.Decrypt(dst[6*bs:7*bs], src[6*bs:7*bs])
    b.Decrypt(dst[7*bs:8*bs], src[7*bs:8*bs])
}
