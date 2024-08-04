package anubis

import (
    "github.com/deatil/go-cryptobin/cipher/anubis"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 16, 20, 24, 28, 32, 36, and 40 bytes.
type EncryptAnubis struct {}

// 加密 / Encrypt
func (this EncryptAnubis) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := anubis.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptAnubis) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := anubis.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Anubis
// The key argument should be 16, 20, 24, 28, 32, 36, and 40 bytes.
var Anubis = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Anubis, func() string {
        return "Anubis"
    })

    crypto.UseEncrypt.Add(Anubis, func() crypto.IEncrypt {
        return EncryptAnubis{}
    })
}
