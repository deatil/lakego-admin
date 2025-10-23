package aescfb

import (
    "io"
    "errors"
    "crypto/aes"
    "crypto/rand"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

type EncryptAesCFB struct {}

// 加密
// Encrypt
func (this EncryptAesCFB) Encrypt(origData []byte, opt crypto.IOption) ([]byte, error) {
    key := opt.Key()

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    encrypted := make([]byte, aes.BlockSize + len(origData))

    iv := encrypted[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(encrypted[aes.BlockSize:], origData)

    return encrypted, nil
}

// 解密
// Decrypt
func (this EncryptAesCFB) Decrypt(encrypted []byte, opt crypto.IOption) ([]byte, error) {
    key := opt.Key()

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(encrypted) < aes.BlockSize {
        err := errors.New("go-cryptobin/crypto: ciphertext too short")
        return nil, err
    }

    iv := encrypted[:aes.BlockSize]
    encoded := encrypted[aes.BlockSize:]

    dst := make([]byte, len(encoded))
    cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, encoded)

    return dst, nil
}

// 特殊的 AesCFB 组合模式
// 也可以使用: MultipleBy(AesCFB)
// AesCFB Encrypt type
// and can use MultipleBy(AesCFB)
var AesCFB = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(AesCFB, func() string {
        return "AesCFB"
    })

    crypto.UseEncrypt.Add(AesCFB, func() crypto.IEncrypt {
        return EncryptAesCFB{}
    })
}
