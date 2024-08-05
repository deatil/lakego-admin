package cfb32

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeCFB32 struct {}

// 加密 / Encrypt
func (this ModeCFB32) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB32Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB32) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB32Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// 密码反馈模式, 32字节
// CFB32 mode
var CFB32 = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(CFB32, func() string {
        return "CFB32"
    })

    crypto.UseMode.Add(CFB32, func() crypto.IMode {
        return ModeCFB32{}
    })
}
