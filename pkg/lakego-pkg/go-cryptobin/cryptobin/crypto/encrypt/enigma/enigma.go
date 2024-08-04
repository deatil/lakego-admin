package enigma

import (
    "github.com/deatil/go-cryptobin/cipher/enigma"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Enigma key is 13 bytes.
type EncryptEnigma struct {}

// 加密 / Encrypt
func (this EncryptEnigma) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    c, err := enigma.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptEnigma) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    c, err := enigma.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)

    return dst, nil
}

// Enigma
// The key argument should be 13 bytes.
var Enigma = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Enigma, func() string {
        return "Enigma"
    })

    crypto.UseEncrypt.Add(Enigma, func() crypto.IEncrypt {
        return EncryptEnigma{}
    })
}
