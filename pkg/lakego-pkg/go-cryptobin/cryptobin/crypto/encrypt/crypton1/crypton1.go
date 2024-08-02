package crypton1

import (
    "github.com/deatil/go-cryptobin/cipher/crypton1"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 16, 24, 32 bytes.
type EncryptCrypton1 struct {}

// 加密 / Encrypt
func (this EncryptCrypton1) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := crypton1.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptCrypton1) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := crypton1.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Crypton1
// The key argument should be 16, 24, 32 bytes.
var Crypton1 = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Crypton1, func() string {
        return "Crypton1"
    })

    crypto.UseEncrypt.Add(Crypton1, func() crypto.IEncrypt {
        return EncryptCrypton1{}
    })
}
