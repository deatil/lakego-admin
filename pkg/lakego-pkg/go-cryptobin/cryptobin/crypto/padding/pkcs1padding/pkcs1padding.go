package pkcs1padding

import (
    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

type PKCS1Paddinger struct {}

// Padding 补码模式 / padding type
func (this PKCS1Paddinger) Padding(plainText []byte, blockSize int, opt crypto.IOption) []byte {
    bt := "02"
    if !opt.Config().Has("pkcs1_padding_bt") {
        bt = opt.Config().GetString("pkcs1_padding_bt")
    }

    return tool.NewPadding().PKCS1Padding(plainText, blockSize, bt)
}

// UnPadding 补码模式 / unpadding type
func (this PKCS1Paddinger) UnPadding(cipherText []byte, opt crypto.IOption) ([]byte, error) {
    return tool.NewPadding().PKCS1UnPadding(cipherText)
}

// PKCS1 补码
// PKCS1Padding
var PKCS1Padding = crypto.TypePadding.Generate()

func init() {
    crypto.TypePadding.Names().Add(PKCS1Padding, func() string {
        return "PKCS1Padding"
    })

    crypto.UsePadding.Add(PKCS1Padding, func() crypto.IPadding {
        return PKCS1Paddinger{}
    })
}
