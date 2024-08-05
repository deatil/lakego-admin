package cfb64

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

type ModeCFB64 struct {}

// 加密 / Encrypt
func (this ModeCFB64) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_cipher.NewCFB64Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB64) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_cipher.NewCFB64Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// 密码反馈模式, 64字节
// CFB64 mode
var CFB64 = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(CFB64, func() string {
        return "CFB64"
    })

    crypto.UseMode.Add(CFB64, func() crypto.IMode {
        return ModeCFB64{}
    })
}
