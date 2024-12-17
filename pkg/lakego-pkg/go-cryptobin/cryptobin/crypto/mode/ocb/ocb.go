package ocb

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/mode/ocb"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

type ModeOCB struct {}

// 加密 / Encrypt
func (this ModeOCB) Encrypt(plain []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tag_size")
    if tagSize > 0 {
        aead, err = ocb.NewWithTagSize(block, tagSize)
    } else {
        aead, err = ocb.NewWithNonceSize(block, len(iv))
    }

    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    cryptText := aead.Seal(nil, iv, plain, additional)

    return cryptText, nil
}

// 解密 / Decrypt
func (this ModeOCB) Decrypt(data []byte, block cipher.Block, opt crypto.IOption) ([]byte, error) {
    var aead cipher.AEAD
    var err error

    iv := opt.Iv()

    tagSize := opt.Config().GetInt("tag_size")
    if tagSize > 0 {
        aead, err = ocb.NewWithTagSize(block, tagSize)
    } else {
        aead, err = ocb.NewWithNonceSize(block, len(iv))
    }

    if err != nil {
        return nil, err
    }

    additional := opt.Config().GetBytes("additional")

    dst, err := aead.Open(nil, iv, data, additional)

    return dst, err
}

// ocb nounce size, should be in [0, cipher.block.BlockSize]
var OCB = crypto.TypeMode.Generate()

func init() {
    crypto.TypeMode.Names().Add(OCB, func() string {
        return "OCB"
    })

    crypto.UseMode.Add(OCB, func() crypto.IMode {
        return ModeOCB{}
    })
}
