package mars2

import (
    "github.com/deatil/go-cryptobin/cipher/mars2"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Mars key is 16, 24, 32 bytes.
type EncryptMars2 struct {}

// 加密 / Encrypt
func (this EncryptMars2) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := mars2.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptMars2) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := mars2.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Mars2
// The key argument should be from 128 to 448 bits
var Mars2 = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Mars2, func() string {
        return "Mars2"
    })

    crypto.UseEncrypt.Add(Mars2, func() crypto.IEncrypt {
        return EncryptMars2{}
    })
}
