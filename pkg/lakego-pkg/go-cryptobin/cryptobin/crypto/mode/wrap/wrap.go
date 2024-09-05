package wrap

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_mode "github.com/deatil/go-cryptobin/mode"
)

type ModeWrap struct {}

// 加密 / Encrypt
func (this ModeWrap) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain)+8)
    cryptobin_mode.NewWrapEncrypter(block, iv).CryptBlocks(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeWrap) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data)-8)
    cryptobin_mode.NewWrapDecrypter(block, iv).CryptBlocks(dst, data)

    return dst, nil
}

// Wrap
var Wrap = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(Wrap, func() string {
        return "Wrap"
    })

    crypto.UseMode.Add(Wrap, func() crypto.IMode {
        return ModeWrap{}
    })
}
