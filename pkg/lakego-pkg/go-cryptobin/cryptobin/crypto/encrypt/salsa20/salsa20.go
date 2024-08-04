package salsa20

import (
    "github.com/deatil/go-cryptobin/cipher/salsa20"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Salsa20 key is 32 bytes.
// iv is 16 bytes.
type EncryptSalsa20 struct {}

// 加密 / Encrypt
func (this EncryptSalsa20) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    iv := opt.Iv()

    c, err := salsa20.NewCipher(opt.Key(), iv)
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptSalsa20) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    iv := opt.Iv()

    c, err := salsa20.NewCipher(opt.Key(), iv)
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)

    return dst, nil
}

// Salsa20
// key is 32 bytes, iv is 16 bytes.
var Salsa20 = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Salsa20, func() string {
        return "Salsa20"
    })

    crypto.UseEncrypt.Add(Salsa20, func() crypto.IEncrypt {
        return EncryptSalsa20{}
    })
}
