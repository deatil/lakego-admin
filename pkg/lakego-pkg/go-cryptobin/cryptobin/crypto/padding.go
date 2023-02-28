package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// Padding 补码模式
func (this Cryptobin) Padding(plainText []byte, blockSize int) []byte {
    var plainPadding []byte

    // 补码方式
    padding := tool.NewPadding()

    switch this.padding {
        case ZeroPadding:
            plainPadding = padding.ZeroPadding(plainText, blockSize)
        case PKCS5Padding:
            plainPadding = padding.PKCS5Padding(plainText)
        case PKCS7Padding:
            plainPadding = padding.PKCS7Padding(plainText, blockSize)
        case X923Padding:
            plainPadding = padding.X923Padding(plainText, blockSize)
        case ISO10126Padding:
            plainPadding = padding.ISO10126Padding(plainText, blockSize)
        case ISO7816_4Padding:
            plainPadding = padding.ISO7816_4Padding(plainText, blockSize)
        case ISO97971Padding:
            plainPadding = padding.ISO97971Padding(plainText, blockSize)
        case TBCPadding:
            plainPadding = padding.TBCPadding(plainText, blockSize)
        case PKCS1Padding:
            bt := "02"
            if !this.config.Has("pkcs1_padding_bt") {
                bt = this.config.GetString("pkcs1_padding_bt")
            }

            plainPadding = padding.PKCS1Padding(plainText, blockSize, bt)
        default:
            plainPadding = plainText
    }

    return plainPadding
}

// UnPadding 补码模式
func (this Cryptobin) UnPadding(cipherText []byte) []byte {
    dst := make([]byte, len(cipherText))

    // 补码方式
    padding := tool.NewPadding()

    // 补码模式
    switch this.padding {
        case ZeroPadding:
            dst = padding.ZeroUnPadding(cipherText)
        case PKCS5Padding:
            dst = padding.PKCS5UnPadding(cipherText)
        case PKCS7Padding:
            dst = padding.PKCS7UnPadding(cipherText)
        case X923Padding:
            dst = padding.X923UnPadding(cipherText)
        case ISO10126Padding:
            dst = padding.ISO10126UnPadding(cipherText)
        case ISO7816_4Padding:
            dst = padding.ISO7816_4UnPadding(cipherText)
        case ISO97971Padding:
            dst = padding.ISO97971UnPadding(cipherText)
        case TBCPadding:
            dst = padding.TBCUnPadding(cipherText)
        case PKCS1Padding:
            dst = padding.PKCS1UnPadding(cipherText)
        default:
            dst = cipherText
    }

    return dst
}
