package hctr

import (
    "crypto/cipher"
)

type hctrEncrypter struct {
    h *hctr
}

func newHCTREncrypter(cip cipher.Block, tweak, hkey []byte) cipher.BlockMode {
    c, err := NewHCTR(cip, tweak, hkey)
    if err != nil {
        panic("cryptobin/hctr: " + err.Error())
    }

    return &hctrEncrypter{c}
}

func NewHCTREncrypter(cip cipher.Block, tweak, hkey []byte) cipher.BlockMode {
    return newHCTREncrypter(cip, tweak, hkey)
}

func (this *hctrEncrypter) BlockSize() int {
    return blockSize
}

func (this *hctrEncrypter) CryptBlocks(dst, src []byte) {
    this.h.Encrypt(dst, src)
}

type hctrDecrypter struct {
    h *hctr
}

func newHCTRDecrypter(cip cipher.Block, tweak, hkey []byte) cipher.BlockMode {
    c, err := NewHCTR(cip, tweak, hkey)
    if err != nil {
        panic("cryptobin/hctr: " + err.Error())
    }

    return &hctrDecrypter{c}
}

func NewHCTRDecrypter(cip cipher.Block, tweak, hkey []byte) cipher.BlockMode {
    return newHCTRDecrypter(cip, tweak, hkey)
}

func (this *hctrDecrypter) BlockSize() int {
    return blockSize
}

func (this *hctrDecrypter) CryptBlocks(dst, src []byte) {
    this.h.Decrypt(dst, src)
}
