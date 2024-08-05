package gofb

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeGOFB struct {}

// 加密 / Encrypt
func (this ModeGOFB) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewGOFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeGOFB) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewGOFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// GOFB
var GOFB = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(GOFB, func() string {
        return "GOFB"
    })

    crypto.UseMode.Add(GOFB, func() crypto.IMode {
        return ModeGOFB{}
    })
}
