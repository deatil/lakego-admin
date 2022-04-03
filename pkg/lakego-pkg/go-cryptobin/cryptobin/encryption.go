package cryptobin

import (
    "fmt"
    "errors"
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"
)

// Cipher
func (this Cryptobin) CipherBlock(key []byte) (cipher.Block, error) {
    var block cipher.Block
    var err error

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
        return nil, err
    }

    return block, nil
}

// Padding 补码模式
func (this Cryptobin) Padding(plainText []byte, blockSize int) []byte {
    // 补码方式
    var plainPadding []byte
    switch this.padding {
        case "Zero":
            plainPadding = this.ZerosPadding(plainText, blockSize)
        case "Pkcs5":
            plainPadding = this.Pkcs5Padding(plainText)
        case "Pkcs7":
            plainPadding = this.Pkcs7Padding(plainText, blockSize)
        default:
            plainPadding = plainText
    }

    return plainPadding
}

// UnPadding 补码模式
func (this Cryptobin) UnPadding(cipherText []byte) []byte {
    dst := make([]byte, len(cipherText))

    // 补码模式
    switch this.padding {
        case "Zero":
            dst = this.ZerosUnPadding(cipherText)
        case "Pkcs5":
            dst = this.Pkcs5UnPadding(cipherText)
        case "Pkcs7":
            dst = this.Pkcs7UnPadding(cipherText)
    }

    return dst
}

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    // 加密方式
    block, err := this.CipherBlock(this.key)
    if err != nil {
        this.Error = err
        return this
    }

    bs := block.BlockSize()

    // 加密数据
    plainPadding := this.Padding(this.data, bs)
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
        case "GCM":
            gcm, err := cipher.NewGCM(block)
            if err != nil {
                this.Error = fmt.Errorf("cipher.NewGCM(),error:%w", err)
                return this
            }

            nonce, ok := this.config["nonce"]
            if !ok {
                this.Error = fmt.Errorf("GCM error:nonce is empty.")
                return this
            }

            additional, _ := this.config["additional"]

            cryptText = gcm.Seal(nil, nonce, plainPadding, additional)
    }

    this.parsedData = cryptText

    return this
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    // 密钥
    key := this.key

    block, err := this.CipherBlock(key)
    if err != nil {
        this.Error = err
        return this
    }

    bs := block.BlockSize()

    // 解密数据
    cipherText := this.data
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
        case "GCM":
            gcm, err := cipher.NewGCM(block)
            if err != nil {
                this.Error = fmt.Errorf("cipher.NewGCM(),error:%w", err)
                return this
            }

            nonce, ok := this.config["nonce"]
            if !ok {
                this.Error = fmt.Errorf("GCM error:nonce is empty.")
                return this
            }

            additional, _ := this.config["additional"]

            dst, err = gcm.Open(nil, nonce, cipherText, additional)
            if err != nil {
                this.Error = err
                return this
            }
    }

    // 补码模式
    this.parsedData = this.UnPadding(dst)

    return this
}
