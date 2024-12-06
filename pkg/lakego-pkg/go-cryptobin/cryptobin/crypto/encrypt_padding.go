package crypto

import (
    "github.com/deatil/go-cryptobin/padding"
)

type ZeroPaddinger struct {}

// Padding 补码模式 / padding type
func (this ZeroPaddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewZero().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ZeroPaddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewZero().UnPadding(cipherText)
}

// ===================

type PKCS5Paddinger struct {}

// Padding 补码模式 / padding type
func (this PKCS5Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewPKCS5().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this PKCS5Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewPKCS5().UnPadding(cipherText)
}

// ===================

type PKCS7Paddinger struct {}

// Padding 补码模式 / padding type
func (this PKCS7Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewPKCS7().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this PKCS7Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewPKCS7().UnPadding(cipherText)
}

// ===================

type X923Paddinger struct {}

// Padding 补码模式 / padding type
func (this X923Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewX923().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this X923Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewX923().UnPadding(cipherText)
}

// ===================

type ISO10126Paddinger struct {}

// Padding 补码模式 / padding type
func (this ISO10126Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewISO10126().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ISO10126Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewISO10126().UnPadding(cipherText)
}

// ===================

type ISO7816_4Paddinger struct {}

// Padding 补码模式 / padding type
func (this ISO7816_4Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewISO7816_4().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ISO7816_4Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewISO7816_4().UnPadding(cipherText)
}

// ===================

type ISO97971Paddinger struct {}

// Padding 补码模式 / padding type
func (this ISO97971Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewISO97971().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ISO97971Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewISO97971().UnPadding(cipherText)
}

// ===================

type PBOC2Paddinger struct {}

// Padding 补码模式 / padding type
func (this PBOC2Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewPBOC2().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this PBOC2Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewPBOC2().UnPadding(cipherText)
}

// ===================

type TBCPaddinger struct {}

// Padding 补码模式 / padding type
func (this TBCPaddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return padding.NewTBC().Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this TBCPaddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return padding.NewTBC().UnPadding(cipherText)
}

// ===================

type NoPaddinger struct {}

// Padding 补码模式 / padding type
func (this NoPaddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return plainText
}

// UnPadding 补码模式 / unpadding type
func (this NoPaddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return cipherText, nil
}

// ===================

func init() {
    UsePadding.Add(ZeroPadding, func() IPadding {
        return ZeroPaddinger{}
    })
    UsePadding.Add(PKCS5Padding, func() IPadding {
        return PKCS5Paddinger{}
    })
    UsePadding.Add(PKCS7Padding, func() IPadding {
        return PKCS7Paddinger{}
    })
    UsePadding.Add(X923Padding, func() IPadding {
        return X923Paddinger{}
    })
    UsePadding.Add(ISO10126Padding, func() IPadding {
        return ISO10126Paddinger{}
    })
    UsePadding.Add(ISO7816_4Padding, func() IPadding {
        return ISO7816_4Paddinger{}
    })
    UsePadding.Add(ISO97971Padding, func() IPadding {
        return ISO97971Paddinger{}
    })
    UsePadding.Add(PBOC2Padding, func() IPadding {
        return PBOC2Paddinger{}
    })
    UsePadding.Add(TBCPadding, func() IPadding {
        return TBCPaddinger{}
    })
    UsePadding.Add(NoPadding, func() IPadding {
        return NoPaddinger{}
    })
}
