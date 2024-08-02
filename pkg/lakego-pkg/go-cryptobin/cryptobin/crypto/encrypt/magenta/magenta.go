package magenta

import (
    "github.com/deatil/go-cryptobin/cipher/magenta"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 16, 24, 32 bytes.
type EncryptMagenta struct {}

// 加密 / Encrypt
func (this EncryptMagenta) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := magenta.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptMagenta) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := magenta.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Magenta
// The key argument should be 16, 24, 32 bytes.
var Magenta = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Magenta, func() string {
        return "Magenta"
    })

    crypto.UseEncrypt.Add(Magenta, func() crypto.IEncrypt {
        return EncryptMagenta{}
    })
}
