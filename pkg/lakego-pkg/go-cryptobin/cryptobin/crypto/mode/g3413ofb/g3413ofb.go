package g3413ofb

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
    cryptobin_mode "github.com/deatil/go-cryptobin/mode"
)

type ModeG3413OFB struct {}

// 加密 / Encrypt
func (this ModeG3413OFB) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    cryptText := make([]byte, len(plain))
    cryptobin_mode.NewG3413OFB(block, iv).XORKeyStream(cryptText, plain)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeG3413OFB) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    // 向量 / iv
    iv := opt.Iv()

    dst := make([]byte, len(data))
    cryptobin_mode.NewG3413OFB(block, iv).XORKeyStream(dst, data)

    return dst, nil
}

// G3413OFB
var G3413OFB = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(G3413OFB, func() string {
        return "G3413OFB"
    })

    crypto.UseMode.Add(G3413OFB, func() crypto.IMode {
        return ModeG3413OFB{}
    })
}
