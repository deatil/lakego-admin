package e2

import (
    "github.com/deatil/go-cryptobin/cipher/e2"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 16, 24, 32 bytes.
type EncryptE2 struct {}

// 加密 / Encrypt
func (this EncryptE2) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := e2.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptE2) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := e2.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// E2
// The key argument should be 16, 24, 32 bytes.
var E2 = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(E2, func() string {
        return "E2"
    })

    crypto.UseEncrypt.Add(E2, func() crypto.IEncrypt {
        return EncryptE2{}
    })
}
