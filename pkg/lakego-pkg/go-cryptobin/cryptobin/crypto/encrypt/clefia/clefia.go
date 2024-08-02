package clefia

import (
    "github.com/deatil/go-cryptobin/cipher/clefia"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 16, 24, 32 bytes.
type EncryptClefia struct {}

// 加密 / Encrypt
func (this EncryptClefia) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := clefia.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptClefia) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := clefia.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Clefia
// The key argument should be 16, 24, 32 bytes.
var Clefia = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Clefia, func() string {
        return "Clefia"
    })

    crypto.UseEncrypt.Add(Clefia, func() crypto.IEncrypt {
        return EncryptClefia{}
    })
}
