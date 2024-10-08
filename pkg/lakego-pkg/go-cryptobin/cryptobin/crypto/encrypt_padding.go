package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

var usePadding = tool.NewPadding()

type ZeroPaddinger struct {}

// Padding 补码模式 / padding type
func (this ZeroPaddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.ZeroPadding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ZeroPaddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.ZeroUnPadding(cipherText)
}

// ===================

type PKCS5Paddinger struct {}

// Padding 补码模式 / padding type
func (this PKCS5Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.PKCS5Padding(plainText)
}

// UnPadding 补码模式 / unpadding type
func (this PKCS5Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.PKCS5UnPadding(cipherText)
}

// ===================

type PKCS7Paddinger struct {}

// Padding 补码模式 / padding type
func (this PKCS7Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.PKCS7Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this PKCS7Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.PKCS7UnPadding(cipherText)
}

// ===================

type X923Paddinger struct {}

// Padding 补码模式 / padding type
func (this X923Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.X923Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this X923Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.X923UnPadding(cipherText)
}

// ===================

type ISO10126Paddinger struct {}

// Padding 补码模式 / padding type
func (this ISO10126Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.ISO10126Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ISO10126Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.ISO10126UnPadding(cipherText)
}

// ===================

type ISO7816_4Paddinger struct {}

// Padding 补码模式 / padding type
func (this ISO7816_4Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.ISO7816_4Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ISO7816_4Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.ISO7816_4UnPadding(cipherText)
}

// ===================

type ISO97971Paddinger struct {}

// Padding 补码模式 / padding type
func (this ISO97971Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.ISO97971Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this ISO97971Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.ISO97971UnPadding(cipherText)
}

// ===================

type PBOC2Paddinger struct {}

// Padding 补码模式 / padding type
func (this PBOC2Paddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.PBOC2Padding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this PBOC2Paddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.PBOC2UnPadding(cipherText)
}

// ===================

type TBCPaddinger struct {}

// Padding 补码模式 / padding type
func (this TBCPaddinger) Padding(plainText []byte, blockSize int, opt IOption) []byte {
    return usePadding.TBCPadding(plainText, blockSize)
}

// UnPadding 补码模式 / unpadding type
func (this TBCPaddinger) UnPadding(cipherText []byte, opt IOption) ([]byte, error) {
    return usePadding.TBCUnPadding(cipherText)
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
