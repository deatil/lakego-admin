package square

import (
    "github.com/deatil/go-cryptobin/cipher/square"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 16 bytes.
type EncryptSquare struct {}

// 加密 / Encrypt
func (this EncryptSquare) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := square.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptSquare) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := square.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Square
// The key argument should be 16 bytes.
var Square = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Square, func() string {
        return "Square"
    })

    crypto.UseEncrypt.Add(Square, func() crypto.IEncrypt {
        return EncryptSquare{}
    })
}
