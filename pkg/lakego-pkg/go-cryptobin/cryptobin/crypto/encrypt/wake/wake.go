package wake

import (
    "github.com/deatil/go-cryptobin/cipher/wake"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// Wake key is 16 bytes.
type EncryptWake struct {}

// 加密 / Encrypt
func (this EncryptWake) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    c, err := wake.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    c.Encrypt(dst, data)

    return dst, nil
}

// 解密 / Decrypt
func (this EncryptWake) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    c, err := wake.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))

    c.Decrypt(dst, data)

    return dst, nil
}

// Wake
// The key argument should be 16 bytes.
var Wake = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Wake, func() string {
        return "Wake"
    })

    crypto.UseEncrypt.Add(Wake, func() crypto.IEncrypt {
        return EncryptWake{}
    })
}
