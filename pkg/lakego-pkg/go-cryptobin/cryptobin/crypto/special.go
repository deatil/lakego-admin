package crypto

import (
    "io"
    "errors"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

// 加密
func (this Cryptobin) AesCFBEncrypt() Cryptobin {
    origData := this.data
    key := this.key

    block, err := aes.NewCipher(key)
    if err != nil {
        return this.AppendError(err)
    }

    encrypted := make([]byte, aes.BlockSize + len(origData))

    iv := encrypted[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return this.AppendError(err)
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(encrypted[aes.BlockSize:], origData)

    this.parsedData = encrypted

    return this
}

// 解密
func (this Cryptobin) AesCFBDecrypt() Cryptobin {
    encrypted := this.data
    key := this.key

    block, err := aes.NewCipher(key)
    if err != nil {
        return this.AppendError(err)
    }

    if len(encrypted) < aes.BlockSize {
        err := errors.New("Cryptobin: [AesCFBDecrypt()] ciphertext too short")
        return this.AppendError(err)
    }

    iv := encrypted[:aes.BlockSize]
    encrypted = encrypted[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(encrypted, encrypted)

    this.parsedData = encrypted

    return this
}

func (this Cryptobin) AesECBEncrypt() Cryptobin {
    origData := this.data
    key := this.key

    cipher, err := aes.NewCipher(this.AesECBGenerateKey(key))
    if err != nil {
        return this.AppendError(err)
    }

    length := (len(origData) + aes.BlockSize) / aes.BlockSize
    plain := make([]byte, length*aes.BlockSize)
    copy(plain, origData)
    pad := byte(len(plain) - len(origData))
    for i := len(origData); i < len(plain); i++ {
        plain[i] = pad
    }

    encrypted := make([]byte, len(plain))

    // 分组分块加密
    for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Encrypt(encrypted[bs:be], plain[bs:be])
    }

    this.parsedData = encrypted

    return this
}

func (this Cryptobin) AesECBDecrypt() Cryptobin {
    encrypted := this.data
    key := this.key

    cipher, err := aes.NewCipher(this.AesECBGenerateKey(key))
    if err != nil {
        return this.AppendError(err)
    }

    decrypted := make([]byte, len(encrypted))

    for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
    }

    trim := 0
    if len(decrypted) > 0 {
        trim = len(decrypted) - int(decrypted[len(decrypted)-1])
    }

    this.parsedData = decrypted[:trim]

    return this
}

func (this Cryptobin) AesECBGenerateKey(key []byte) (genKey []byte) {
    genKey = make([]byte, 16)
    copy(genKey, key)
    for i := 16; i < len(key); {
        for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
            genKey[j] ^= key[i]
        }
    }

    return genKey
}
