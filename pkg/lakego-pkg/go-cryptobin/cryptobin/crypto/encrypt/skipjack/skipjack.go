package skipjack

import (
    "github.com/deatil/go-cryptobin/cipher/skipjack"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Skipjack key is 10 bytes.
type EncryptSkipjack struct {}

// 加密 / Encrypt
func (this EncryptSkipjack) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := skipjack.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptSkipjack) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := skipjack.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// Skipjack
// The key argument should be 10 bytes.
var Skipjack = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Skipjack, func() string {
        return "Skipjack"
    })

    crypto.UseEncrypt.Add(Skipjack, func() crypto.IEncrypt {
        return EncryptSkipjack{}
    })
}
