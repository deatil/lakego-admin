package pkcs1

import (
    "github.com/deatil/go-cryptobin/padding"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

type PKCS1Paddinger struct {}

// Padding 补码模式 / padding type
func (this PKCS1Paddinger) Padding(plainText []byte, blockSize int, opt crypto.IOption) []byte {
    bt := "02"
    if !opt.Config().Has("pkcs1_padding_bt") {
        bt = opt.Config().GetString("pkcs1_padding_bt")
    }

    return padding.NewPKCS1(bt).Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this PKCS1Paddinger) UnPadding(cipherText []byte, opt crypto.IOption) ([]byte, error) {
    bt := "02"
    if !opt.Config().Has("pkcs1_padding_bt") {
        bt = opt.Config().GetString("pkcs1_padding_bt")
    }

    return padding.NewPKCS1(bt).UnPadding(cipherText)
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
