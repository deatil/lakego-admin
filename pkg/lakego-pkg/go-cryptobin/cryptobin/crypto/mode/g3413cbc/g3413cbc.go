package g3413cbc

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeG3413CBC struct {}

// 加密 / Encrypt
func (this ModeG3413CBC) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewG3413CBCEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeG3413CBC) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewG3413CBCDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

// G3413CBC
var G3413CBC = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(G3413CBC, func() string {
        return "G3413CBC"
    })

    crypto.UseMode.Add(G3413CBC, func() crypto.IMode {
        return ModeG3413CBC{}
    })
}
