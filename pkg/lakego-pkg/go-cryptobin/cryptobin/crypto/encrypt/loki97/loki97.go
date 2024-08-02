package loki97

import (
    "github.com/deatil/go-cryptobin/cipher/loki97"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Loki97 key is 16, 24, 32 bytes.
type EncryptLoki97 struct {}

// 加密 / Encrypt
func (this EncryptLoki97) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := loki97.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptLoki97) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := loki97.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Loki97
// The key argument should be 16, 24, 32 bytes.
var Loki97 = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Loki97, func() string {
        return "Loki97"
    })

    crypto.UseEncrypt.Add(Loki97, func() crypto.IEncrypt {
        return EncryptLoki97{}
    })
}
