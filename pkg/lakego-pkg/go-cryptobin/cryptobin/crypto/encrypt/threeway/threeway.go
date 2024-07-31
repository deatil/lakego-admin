package threeway

import (
    "github.com/deatil/go-cryptobin/cipher/threeway"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

type EncryptThreeway struct {}

// 加密 / Encrypt
func (this EncryptThreeway) Encrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := threeway.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockEncrypt(block, data, opt)
}

// 解密 / Decrypt
func (this EncryptThreeway) Decrypt(data []byte, opt crypto.IOption) ([]byte, error) {
    block, err := threeway.NewCipher(opt.Key())
    if err != nil {
        return nil, err
    }

    return crypto.BlockDecrypt(block, data, opt)
}

// 生成标识
// make Type Multiple
var Threeway = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(Threeway, func() string {
        return "Threeway"
    })

    crypto.UseEncrypt.Add(Threeway, func() crypto.IEncrypt {
        return EncryptThreeway{}
    })
}
