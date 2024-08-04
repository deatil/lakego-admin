package mars

import (
    "github.com/deatil/go-cryptobin/cipher/mars"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Mars key is 16, 24, 32 bytes.
type EncryptMars struct {}

// 加密 / Encrypt
func (this EncryptMars) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := mars.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptMars) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := mars.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Mars
// The key argument should be 16, 24, 32 bytes.
var Mars = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Mars, func() string {
        return "Mars"
    })

    crypto.UseEncrypt.Add(Mars, func() crypto.IEncrypt {
        return EncryptMars{}
    })
}
