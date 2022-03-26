package cryptobin

import (
    "fmt"
    "errors"
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"
)

// 加密
func (this Crypto) Encrypt() Crypto {
    var block cipher.Block
    var err error

    // 密钥
    key := this.Key

    switch this.Type {
        case "Aes":
            // NewCipher creates and returns a new cipher.Block.
            // The key argument should be the AES key,
            // either 16, 24, or 32 bytes to select
            // AES-128, AES-192, or AES-256.
            block, err = aes.NewCipher(key)
        case "Des":
            block, err = des.NewCipher(key)
        case "TriDes":
            block, err = des.NewTripleDESCipher(key)
    }

    if err != nil {
        this.Error = err

        return this
    }

    bs := block.BlockSize()

    // 加密数据
    plainText := this.Data

    var plainPadding []byte
        switch this.Padding {
            case "Zero":
                plainPadding = this.ZerosPadding(plainText, bs)
            case "Pkcs5":
                plainPadding = this.Pkcs5Padding(plainText)
            case "Pkcs7":
                plainPadding = this.Pkcs7Padding(plainText, bs)
            default:
                plainPadding = plainText
    }

    if len(plainPadding)%bs != 0 {
        this.Error = errors.New(fmt.Sprintf("the length of the completed data must be an integer multiple of the block, the completed data size is %d, block size is %d", len(plainPadding), bs))

        return this
    }

    // 向量
    iv := this.Iv

    cryptText := make([]byte, len(plainPadding))
    switch this.Mode {
        case "ECB":
            dst := cryptText
            for len(plainPadding) > 0 {
                block.Encrypt(dst, plainPadding[:bs])
                plainPadding = plainPadding[bs:]
                dst = dst[bs:]
            }
        case "CBC":
            cipher.NewCBCEncrypter(block, iv).CryptBlocks(cryptText, plainPadding)
        case "CFB":
            cipher.NewCFBEncrypter(block, iv).XORKeyStream(cryptText, plainPadding)
        case "OFB":
            cipher.NewOFB(block, iv).XORKeyStream(cryptText, plainPadding)
        case "CTR":
            cipher.NewCTR(block, iv).XORKeyStream(cryptText, plainPadding)
    }

    this.ParsedData = cryptText

    return this
}

// 解密
func (this Crypto) Decrypt() Crypto {
    var block cipher.Block
    var err error

    // 密钥
    key := this.Key

    switch this.Type {
        case "Aes":
            block, err = aes.NewCipher(key)
        case "Des":
            block, err = des.NewCipher(key)
        case "TriDes":
            block, err = des.NewTripleDESCipher(key)
    }

    if err != nil {
        this.Error = err
        return this
    }

    // 解密数据
    cipherText := this.Data

    bs := block.BlockSize()
    if len(cipherText)%bs != 0 {
        this.Error = errors.New(fmt.Sprintf("improper decrypt type, block size is %d", bs))
        return this
    }

    // 向量
    iv := this.Iv

    dst := make([]byte, len(cipherText))

    switch this.Mode {
        case "ECB":
            dstTmp := dst
            for len(cipherText) > 0 {
                block.Decrypt(dstTmp, cipherText[:bs])
                cipherText = cipherText[bs:]
                dstTmp = dstTmp[bs:]
            }
        case "CBC":
            cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, cipherText)
        case "CFB":
            cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, cipherText)
        case "OFB":
            cipher.NewOFB(block, iv).XORKeyStream(dst, cipherText)
        case "CTR":
            cipher.NewCTR(block, iv).XORKeyStream(dst, cipherText)
    }

    switch this.Padding {
        case "Zero":
            dst = this.ZerosUnPadding(dst)
        case "Pkcs5":
            dst = this.Pkcs5UnPadding(dst)
        case "Pkcs7":
            dst = this.Pkcs7UnPadding(dst)
    }

    this.ParsedData = dst

    return this
}

// 加密 RSA
func (this Crypto) EnRsa() Crypto {
    this.ParsedData, this.Error = NewRsa().Encrypt(this.Data, this.Key)

    return this
}

// 解密 RSA
func (this Crypto) DeRsa(password ...string) Crypto {
    this.ParsedData, this.Error = NewRsa().Decrypt(this.Data, this.Key, password...)

    return this
}
