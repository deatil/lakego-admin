package cryptobin

import (
    "fmt"
    "errors"
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"
)

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    var block cipher.Block
    var err error

    // 密钥
    key := this.key

    // 加密类型
    switch this.multiple {
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
    plainText := this.data

    // 补码方式
    var plainPadding []byte
    switch this.padding {
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
    iv := this.iv

    // 模式
    cryptText := make([]byte, len(plainPadding))
    switch this.mode {
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

    this.parsedData = cryptText

    return this
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    var block cipher.Block
    var err error

    // 密钥
    key := this.key

    // 加密类型
    switch this.multiple {
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
    cipherText := this.data

    bs := block.BlockSize()
    if len(cipherText)%bs != 0 {
        this.Error = errors.New(fmt.Sprintf("improper decrypt type, block size is %d", bs))
        return this
    }

    // 向量
    iv := this.iv

    dst := make([]byte, len(cipherText))

    // 加密模式
    switch this.mode {
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

    // 补码模式
    switch this.padding {
        case "Zero":
            dst = this.ZerosUnPadding(dst)
        case "Pkcs5":
            dst = this.Pkcs5UnPadding(dst)
        case "Pkcs7":
            dst = this.Pkcs7UnPadding(dst)
    }

    this.parsedData = dst

    return this
}

// RSA 加密
func (this Cryptobin) RsaEncrypt() Cryptobin {
    this.parsedData, this.Error = NewRsa().Encrypt(this.data, this.key)

    return this
}

// RSA 解密
func (this Cryptobin) RsaDecrypt(password ...string) Cryptobin {
    this.parsedData, this.Error = NewRsa().Decrypt(this.data, this.key, password...)

    return this
}

// RSA 私钥加密
func (this Cryptobin) RsaPrikeyEncrypt(password ...string) Cryptobin {
    this.parsedData, this.Error = NewRsa().PriKeyEncrypt(this.data, this.key, password...)

    return this
}

// RSA 公钥解密
func (this Cryptobin) RsaPubkeyDecrypt() Cryptobin {
    this.parsedData, this.Error = NewRsa().PubKeyDecrypt(this.data, this.key)

    return this
}
