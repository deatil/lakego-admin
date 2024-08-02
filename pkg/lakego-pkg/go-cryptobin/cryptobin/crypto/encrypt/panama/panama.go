package panama

import (
    "github.com/deatil/go-cryptobin/cipher/panama"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// The key argument should be 32 bytes.
type EncryptPanama struct {}

// 加密 / Encrypt
func (this EncryptPanama) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    c, err := panama.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptPanama) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    c, err := panama.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)

    return dst, nil
}

// Panama
// The key argument should be 32 bytes.
var Panama = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Panama, func() string {
        return "Panama"
    })

    crypto.UseEncrypt.Add(Panama, func() crypto.IEncrypt {
        return EncryptPanama{}
    })
}
