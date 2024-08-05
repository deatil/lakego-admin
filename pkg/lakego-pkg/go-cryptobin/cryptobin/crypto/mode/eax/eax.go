package eax

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cipher/eax"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// eax nounce(iv) size, should be in > 0
type ModeEAX struct {}

// 加密 / Encrypt
func (this ModeEAX) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    iv := opt.Iv()

    aead, err := eax.NewEAXWithNonceSize(block, len(iv))
    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, iv, plain, additional)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeEAX) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    iv := opt.Iv()

    aead, err := eax.NewEAXWithNonceSize(block, len(iv))
    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, iv, data, additional)

    return dst, err
}

// EAX
// EAX nounce size, should be in > 0
var EAX = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(EAX, func() string {
        return "EAX"
    })

    crypto.UseMode.Add(EAX, func() crypto.IMode {
        return ModeEAX{}
    })
}
