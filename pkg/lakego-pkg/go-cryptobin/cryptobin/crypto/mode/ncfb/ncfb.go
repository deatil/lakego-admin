package ncfb

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_mode "github.com/deatil/go-cryptobin/mode"
)

type ModeNCFB struct {}

// 加密 / Encrypt
func (this ModeNCFB) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_mode.NewNCFBEncrypter(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeNCFB) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewNCFBDecrypter(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// NCFB mode
var NCFB = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(NCFB, func() string {
        return "NCFB"
    })

    crypto.UseMode.Add(NCFB, func() crypto.IMode {
        return ModeNCFB{}
    })
}
