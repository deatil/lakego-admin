package noekeon

import (
    "github.com/deatil/go-cryptobin/cipher/noekeon"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 16 bytes.
type EncryptNoekeon struct {}

// 加密 / Encrypt
func (this EncryptNoekeon) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := noekeon.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptNoekeon) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := noekeon.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Noekeon
// The key argument should be 16 bytes.
var Noekeon = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Noekeon, func() string {
        return "Noekeon"
    })

    crypto.UseEncrypt.Add(Noekeon, func() crypto.IEncrypt {
        return EncryptNoekeon{}
    })
}
