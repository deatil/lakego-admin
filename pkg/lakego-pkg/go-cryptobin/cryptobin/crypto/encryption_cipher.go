package crypto

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

    "github.com/tjfoc/gmsm/sm4"

    cryptobin_rc2 "github.com/deatil/go-cryptobin/cipher/rc2"
    cryptobin_rc5 "github.com/deatil/go-cryptobin/cipher/rc5"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

// 加密
func (this Cryptobin) CipherEncrypt() Cryptobin {
    // 加密方式
    block, err := this.CipherBlock(this.key)
    if err != nil {
        return this.AppendError(err)
    }

    bs := block.BlockSize()

    // 加密数据
    plainPadding := this.Padding(this.data, bs)

    // 补码后需要验证
    if this.padding != NoPadding {
        if len(plainPadding)%bs != 0 {
            err := errors.New(fmt.Sprintf("Cryptobin: [CipherEncrypt()] the length of the completed data must be an integer multiple of the block, the completed data size is %d, block size is %d", len(plainPadding), bs))
            return this.AppendError(err)
        }
    }

    // 向量
    iv := this.iv

    // 模式
    cryptText := make([]byte, len(plainPadding))
    switch this.mode {
        case ECB:
            dst := cryptText
            for len(plainPadding) > 0 {
                block.Encrypt(dst, plainPadding[:bs])
                plainPadding = plainPadding[bs:]
                dst = dst[bs:]
            }
        case CBC:
            cipher.NewCBCEncrypter(block, iv).CryptBlocks(cryptText, plainPadding)
        case CFB:
            cipher.NewCFBEncrypter(block, iv).XORKeyStream(cryptText, plainPadding)
        case CFB8:
            cryptobin_cipher.NewCFB8Encrypter(block, iv).XORKeyStream(cryptText, plainPadding)
        case OFB:
            cipher.NewOFB(block, iv).XORKeyStream(cryptText, plainPadding)
        case OFB8:
            cryptobin_cipher.NewOFB8(block, iv).XORKeyStream(cryptText, plainPadding)
        case CTR:
            cipher.NewCTR(block, iv).XORKeyStream(cryptText, plainPadding)
        case GCM:
            nonceBytes := this.config.GetBytes("nonce")
            if nonceBytes == nil {
                err := fmt.Errorf("Cryptobin: [CipherEncrypt()] GCM error:nonce is empty.")
                return this.AppendError(err)
            }

            aead, err := cipher.NewGCMWithNonceSize(block, len(nonceBytes))
            if err != nil {
                err = fmt.Errorf("Cryptobin: [CipherEncrypt()] cipher.NewGCMWithNonceSize(),error:%w", err)
                return this.AppendError(err)
            }

            additionalBytes := this.config.GetBytes("additional")

            cryptText = aead.Seal(nil, nonceBytes, plainPadding, additionalBytes)
        case CCM:
            nonceBytes := this.config.GetBytes("nonce")
            if nonceBytes == nil {
                err := fmt.Errorf("Cryptobin: [CipherEncrypt()] CCM error:nonce is empty.")
                return this.AppendError(err)
            }

            aead, err := cryptobin_cipher.NewCCMWithNonceSize(block, len(nonceBytes))
            if err != nil {
                err = fmt.Errorf("Cryptobin: [CipherEncrypt()] cipher.NewCCMWithNonceSize(),error:%w", err)
                return this.AppendError(err)
            }

            additionalBytes := this.config.GetBytes("additional")

            cryptText = aead.Seal(nil, nonceBytes, plainPadding, additionalBytes)
        default:
            err := fmt.Errorf("Cryptobin: [CipherEncrypt()] Mode [%s] is error.", this.mode)
            return this.AppendError(err)
    }

    this.parsedData = cryptText

    return this
}

// 解密
func (this Cryptobin) CipherDecrypt() Cryptobin {
    // 密钥
    key := this.key

    block, err := this.CipherBlock(key)
    if err != nil {
        return this.AppendError(err)
    }

    bs := block.BlockSize()

    // 解密数据
    cipherText := this.data

    // 补码后需要验证
    if this.padding != NoPadding {
        if len(cipherText)%bs != 0 {
            err := errors.New(fmt.Sprintf("Cryptobin: [CipherDecrypt()] improper decrypt type, block size is %d", bs))
            return this.AppendError(err)
        }
    }

    // 向量
    iv := this.iv

    dst := make([]byte, len(cipherText))

    // 加密模式
    switch this.mode {
        case ECB:
            dstTmp := dst
            for len(cipherText) > 0 {
                block.Decrypt(dstTmp, cipherText[:bs])
                cipherText = cipherText[bs:]
                dstTmp = dstTmp[bs:]
            }
        case CBC:
            cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, cipherText)
        case CFB:
            cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, cipherText)
        case CFB8:
            cryptobin_cipher.NewCFB8Decrypter(block, iv).XORKeyStream(dst, cipherText)
        case OFB:
            cipher.NewOFB(block, iv).XORKeyStream(dst, cipherText)
        case OFB8:
            cryptobin_cipher.NewOFB8(block, iv).XORKeyStream(dst, cipherText)
        case CTR:
            cipher.NewCTR(block, iv).XORKeyStream(dst, cipherText)
        case GCM:
            nonceBytes := this.config.GetBytes("nonce")
            if nonceBytes == nil {
                err = fmt.Errorf("Cryptobin: [CipherDecrypt()] CCM error:nonce is empty.")
                return this.AppendError(err)
            }

            gcm, err := cipher.NewGCMWithNonceSize(block, len(nonceBytes))
            if err != nil {
                err = fmt.Errorf("Cryptobin: [CipherDecrypt()] cipher.NewGCMWithNonceSize(),error:%w", err)
                return this.AppendError(err)
            }

            additionalBytes := this.config.GetBytes("additional")

            dst, err = gcm.Open(nil, nonceBytes, cipherText, additionalBytes)
            if err != nil {
                return this.AppendError(err)
            }
        case CCM:
            // ccm nounce size, should be in [7,13]
            nonceBytes := this.config.GetBytes("nonce")
            if nonceBytes == nil {
                err = fmt.Errorf("Cryptobin: [CipherDecrypt()] GCM error:nonce is empty.")
                return this.AppendError(err)
            }

            aead, err := cryptobin_cipher.NewCCMWithNonceSize(block, len(nonceBytes))
            if err != nil {
                err = fmt.Errorf("Cryptobin: [CipherDecrypt()] cipher.NewCCMWithNonceSize(),error:%w", err)
                return this.AppendError(err)
            }

            additionalBytes := this.config.GetBytes("additional")

            dst, err = aead.Open(nil, nonceBytes, cipherText, additionalBytes)
            if err != nil {
                return this.AppendError(err)
            }
        default:
            err = fmt.Errorf("Cryptobin: [CipherDecrypt()] Mode [%s] is error.", this.mode)
            return this.AppendError(err)
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
        case Aes:
            // NewCipher creates and returns a new cipher.Block.
            // The key argument should be the AES key,
            // either 16, 24, or 32 bytes to select
            // AES-128, AES-192, or AES-256.
            block, err = aes.NewCipher(key)
        case Des:
            block, err = des.NewCipher(key)
        case TriDes:
            block, err = des.NewTripleDESCipher(key)
        case Twofish:
            // The key argument should be the Twofish key,
            // 16, 24 or 32 bytes.
            block, err = twofish.NewCipher(key)
        case Blowfish:
            if this.config.Has("salt") {
                block, err = blowfish.NewSaltedCipher(key, this.config.GetBytes("salt"))
            } else {
                block, err = blowfish.NewCipher(key)
            }
        case Tea:
            // key is 16 bytes
            if this.config.Has("rounds") {
                block, err = tea.NewCipherWithRounds(key, this.config.GetInt("rounds"))
            } else {
                block, err = tea.NewCipher(key)
            }
        case Xtea:
            // XTEA only supports 128 bit (16 byte) keys.
            block, err = xtea.NewCipher(key)
        case Cast5:
            // Cast5 only supports 128 bit (16 byte) keys.
            block, err = cast5.NewCipher(key)
        case RC2:
            // RC2 key, at least 1 byte and at most 128 bytes.
            block, err = cryptobin_rc2.NewCipher(key, len(key)*8)
        case RC5:
            // wordSize is 32 or 64
            wordSize := uint(32)
            if this.config.Has("word_size") {
                wordSize = this.config.GetUint("word_size")
            }

            // rounds at least 8 byte and at most 127 bytes.
            rounds := uint(64)
            if this.config.Has("rounds") {
                rounds = this.config.GetUint("rounds")
            }

            // RC5 key is 16, 24 or 32 bytes.
            // iv is 8 with 32, 16 with 64
            block, err = cryptobin_rc5.NewCipher(key, wordSize, rounds)
        case SM4:
            // 国密 sm4 加密
            block, err = sm4.NewCipher(key)
    }

    if err != nil {
        return nil, err
    }

    return block, nil
}
