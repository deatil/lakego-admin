package cast256

import (
    "github.com/deatil/go-cryptobin/cipher/cast256"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Cast256 key is 32 bytes.
type EncryptCast256 struct {}

// 加密 / Encrypt
func (this EncryptCast256) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := cast256.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptCast256) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := cast256.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Cast256
// The key argument should be 32 bytes.
var Cast256 = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Cast256, func() string {
        return "Cast256"
    })

    crypto.UseEncrypt.Add(Cast256, func() crypto.IEncrypt {
        return EncryptCast256{}
    })
}
