package cfb16

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_mode "github.com/deatil/go-cryptobin/mode"
)

type ModeCFB16 struct {}

// 加密 / Encrypt
func (this ModeCFB16) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_mode.NewCFB16Encrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeCFB16) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewCFB16Decrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// 密码反馈模式, 16字节
// CFB16 mode
var CFB16 = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(CFB16, func() string {
        return "CFB16"
    })

    crypto.UseMode.Add(CFB16, func() crypto.IMode {
        return ModeCFB16{}
    })
}
