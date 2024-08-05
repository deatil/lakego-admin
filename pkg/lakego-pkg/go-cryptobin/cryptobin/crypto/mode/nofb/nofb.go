package nofb

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeNOFB struct {}

// 加密 / Encrypt
func (this ModeNOFB) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewNOFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeNOFB) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewNOFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// NOFB mode
var NOFB = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(NOFB, func() string {
        return "NOFB"
    })

    crypto.UseMode.Add(NOFB, func() crypto.IMode {
        return ModeNOFB{}
    })
}
