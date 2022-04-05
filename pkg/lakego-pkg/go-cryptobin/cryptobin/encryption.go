package cryptobin

import (
    "fmt"
    "errors"
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"

    "golang.org/x/crypto/tea"
    "golang.org/x/crypto/xtea"
    "golang.org/x/crypto/cast5"
    "golang.org/x/crypto/twofish"
    "golang.org/x/crypto/blowfish"
    "golang.org/x/crypto/chacha20poly1305"
)

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    // 不通用的处理
    switch this.multiple {
        case "Chacha20poly1305":
            cryptText, err := this.AEADEncrypt()
            if err != nil {
                this.Error = err
                return this
            }

            this.parsedData = cryptText
            return this
    }

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

            cryptText = gcm.Seal(nil, nonce.([]byte), plainPadding, additional.([]byte))
    }

    this.parsedData = cryptText

    return this
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    // 不通用的处理
    switch this.multiple {
        case "Chacha20poly1305":
            dst, err := this.AEADDecrypt()
            if err != nil {
                this.Error = err
                return this
            }

            this.parsedData = dst
            return this
    }

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

            dst, err = gcm.Open(nil, nonce.([]byte), cipherText, additional.([]byte))
            if err != nil {
                this.Error = err
                return this
            }
    }

    // 补码模式
    this.parsedData = this.UnPadding(dst)

    return this
}

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
        case "Twofish":
            // The key argument should be the Twofish key,
            // 16, 24 or 32 bytes.
            block, err = twofish.NewCipher(key)
        case "Blowfish":
            if salt, ok := this.config["salt"]; ok {
                block, err = blowfish.NewSaltedCipher(key, salt.([]byte))
            } else {
                block, err = blowfish.NewCipher(key)
            }
        case "Tea":
            // key is 16 bytes
            if rounds, ok := this.config["rounds"]; ok {
                block, err = tea.NewCipherWithRounds(key, rounds.(int))
            } else {
                block, err = tea.NewCipher(key)
            }
        case "Xtea":
            // XTEA only supports 128 bit (16 byte) keys.
            block, err = xtea.NewCipher(key)
        case "Cast5":
            block, err = cast5.NewCipher(key)
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

// 不通用的加密
func (this Cryptobin) AEADEncrypt() ([]byte, error) {
    var err2 error

    switch this.multiple {
        // 32 bytes
        case "Chacha20poly1305":
            chacha, err := chacha20poly1305.New(this.key)
            if err != nil {
                err2 = fmt.Errorf("chacha20poly1305.New(),error:%w", err)
                return nil, err2
            }

            nonce, ok := this.config["nonce"]
            if !ok {
                err2 = fmt.Errorf("chacha20poly1305 error: nonce is empty.")
                return nil, err2
            }

            additional, _ := this.config["additional"]

            cryptText := chacha.Seal(nil, nonce.([]byte), this.data, additional.([]byte))

            return cryptText, nil
    }

    err2 = fmt.Errorf("Encrypt type error.")

    return nil, err2
}

// 不通用的解密
func (this Cryptobin) AEADDecrypt() ([]byte, error) {
    var err2 error

    switch this.multiple {
        // 32 bytes
        case "Chacha20poly1305":
            chacha, err := chacha20poly1305.New(this.key)
            if err != nil {
                err2 = fmt.Errorf("chacha20poly1305.New(),error:%w", err)
                return nil, err2
            }

            nonce, ok := this.config["nonce"]
            if !ok {
                err2 = fmt.Errorf("chacha20poly1305 error: nonce is empty.")
                return nil, err2
            }

            additional, _ := this.config["additional"]

            dst, err := chacha.Open(nil, nonce.([]byte), this.data, additional.([]byte))
            if err != nil {
                return nil, err
            }

            return dst, nil
    }

    err2 = fmt.Errorf("Decrypt type error.")

    return nil, err2
}
