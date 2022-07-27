package cryptobin

// Padding 补码模式
func (this Cryptobin) Padding(plainText []byte, blockSize int) []byte {
    var plainPadding []byte

    // 补码方式
    padding := NewPadding()

    switch this.padding {
        case "Zero":
            plainPadding = padding.ZeroPadding(plainText, blockSize)
        case "PKCS5":
            plainPadding = padding.PKCS5Padding(plainText)
        case "PKCS7":
            plainPadding = padding.PKCS7Padding(plainText, blockSize)
        case "X923":
            plainPadding = padding.X923Padding(plainText, blockSize)
        case "ISO10126":
            plainPadding = padding.ISO10126Padding(plainText, blockSize)
        case "ISO7816_4":
            plainPadding = padding.ISO7816_4Padding(plainText, blockSize)
        case "TBC":
            plainPadding = padding.TBCPadding(plainText, blockSize)
        case "PKCS1":
            bt, ok := this.config["pkcs1_padding_bt"]
            if !ok {
                bt = "02"
            }

            plainPadding = padding.PKCS1Padding(plainText, blockSize, bt.(string))
        default:
            plainPadding = plainText
    }

    return plainPadding
}

// UnPadding 补码模式
func (this Cryptobin) UnPadding(cipherText []byte) []byte {
    dst := make([]byte, len(cipherText))

    // 补码方式
    padding := NewPadding()

    // 补码模式
    switch this.padding {
        case "Zero":
            dst = padding.ZeroUnPadding(cipherText)
        case "PKCS5":
            dst = padding.PKCS5UnPadding(cipherText)
        case "PKCS7":
            dst = padding.PKCS7UnPadding(cipherText)
        case "X923":
            dst = padding.X923UnPadding(cipherText)
        case "ISO10126":
            dst = padding.ISO10126UnPadding(cipherText)
        case "ISO7816_4":
            dst = padding.ISO7816_4UnPadding(cipherText)
        case "TBC":
            dst = padding.TBCUnPadding(cipherText)
        case "PKCS1":
            dst = padding.PKCS1UnPadding(cipherText)
        default:
            dst = cipherText
    }

    return dst
}
