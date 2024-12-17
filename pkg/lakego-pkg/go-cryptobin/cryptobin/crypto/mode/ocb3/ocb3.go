package ocb3

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/mode/ocb3"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

type ModeOCB3 struct {}

// 加密 / Encrypt
func (this ModeOCB3) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tag_size")
    if tagSize > 0 {
        aead, err = ocb3.NewWithTagSize(block, tagSize)
    } else {
        aead, err = ocb3.NewWithNonceSize(block, len(iv))
    }

    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, iv, plain, additional)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeOCB3) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tag_size")
    if tagSize > 0 {
        aead, err = ocb3.NewWithTagSize(block, tagSize)
    } else {
        aead, err = ocb3.NewWithNonceSize(block, len(iv))
    }

    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, iv, data, additional)

    return dst, err
}

// ocb3 nounce size, should be in [0, cipher.block.BlockSize]
var OCB3 = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(OCB3, func() string {
        return "OCB3"
    })

    crypto.UseMode.Add(OCB3, func() crypto.IMode {
        return ModeOCB3{}
    })
}
