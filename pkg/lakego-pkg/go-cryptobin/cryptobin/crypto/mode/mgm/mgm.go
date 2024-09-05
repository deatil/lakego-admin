package mgm

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/mode/mgm"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// MGM nounce(iv) size, should be 16 bytes
type ModeMGM struct {}

// 加密 / Encrypt
func (this ModeMGM) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    iv := opt.Iv()

    aead, err := mgm.NewMGM(block)
    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")
    cryptText := aead.Seal(nil, iv, plain, additional)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeMGM) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    iv := opt.Iv()

    aead, err := mgm.NewMGM(block)
    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")
    dst, err := aead.Open(nil, iv, data, additional)

    return dst, err
}

// MGM
// MGM nounce(iv) size, should be 16 bytes
var MGM = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(MGM, func() string {
        return "MGM"
    })

    crypto.UseMode.Add(MGM, func() crypto.IMode {
        return ModeMGM{}
    })
}
